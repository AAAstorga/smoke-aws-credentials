// Copyright 2018-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// A copy of the License is located at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//
//  AwsRotatingCredentials.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeAWSCore
import LoggerAPI

#if os(Linux)
	import Glibc
#else
	import Darwin
#endif

internal protocol AsyncAfterScheduler {
    func asyncAfter(deadline: DispatchTime, qos: DispatchQoS,
                    flags: DispatchWorkItemFlags,
                    execute work: @escaping @convention(block) () -> Void)
}

extension DispatchQueue: AsyncAfterScheduler {}

/**
 A protocol that retrieves `ExpiringCredentials` and that is closable.
 */
public protocol ExpiringCredentialsRetriever {
    
    /**
     Gracefully shuts down this retriever. This function is idempotent and
     will handle being called multiple times.
     */
    func close()

    /**
     Waits for the retriever to be closed. If close() is not called,
     this will block forever.
     */
    func wait()
    
    /**
     Retrieves a new instance of `ExpiringCredentials`.
     */
    func get() throws -> ExpiringCredentials
}

/**
 Class that manages the rotating credentials.
 */
public class AwsRotatingCredentialsProvider: StoppableCredentialsProvider {
    public var credentials: Credentials {
        // the provider returns a copy of the current
        // credentials which is used within a request.
        // The provider is then free to rotate credentials
        // without the risk of rotation causing inconsistent
        // credentials to be used across a request.
        return expiringCredentials
    }
    
    private var expiringCredentials: ExpiringCredentials
    static let queue = DispatchQueue(label: "com.amazon.SmokeAWSCredentials.AwsRotatingCredentialsProvider")
    
    enum State {
        case initialized
        case scheduled
        case processing
        case shuttingDown
        case shutDown
    }
    
    let expirationBufferSeconds = 300.0 // 5 minutes
    let validCredentialsRetrySeconds = 60.0 // 1 minute
    let invalidCredentialsRetrySeconds = 3600.0 // 1 hour
    
    var currentWorker: (() -> ())?
    let expiringCredentialsRetriever: ExpiringCredentialsRetriever
    let scheduler: AsyncAfterScheduler
    
    private var state: State = .initialized
    private var stateLock: NSLock = NSLock()
    let shutdownDispatchGroup: DispatchGroup
    
    /**
     Initializer that accepts the initial ExpiringCredentials instance for this provider.
     
     - Parameters:
        - expiringCredentialsRetriever: retriever of expiring credentials.
     */
    public convenience init(expiringCredentialsRetriever: ExpiringCredentialsRetriever) throws {
        try self.init(expiringCredentialsRetriever: expiringCredentialsRetriever,
                      scheduler: AwsRotatingCredentialsProvider.queue)
    }
    
    internal init(expiringCredentialsRetriever: ExpiringCredentialsRetriever,
                  scheduler: AsyncAfterScheduler) throws {
        self.expiringCredentials = try expiringCredentialsRetriever.get()
        self.currentWorker = nil
        self.expiringCredentialsRetriever = expiringCredentialsRetriever
        self.scheduler = scheduler
        self.status = .initialized
        var newMutux = pthread_mutex_t()
        
        var attr = pthread_mutexattr_t()
        guard pthread_mutexattr_init(&attr) == 0 else {
            preconditionFailure()
        }
		
        pthread_mutexattr_settype(&attr, Int32(PTHREAD_MUTEX_NORMAL))
        guard pthread_mutex_init(&newMutux, &attr) == 0 else {
            preconditionFailure()
        }
		pthread_mutexattr_destroy(&attr)
        
        self.statusMutex = newMutux
    }
    
    deinit {
        stop()
        wait()
    }
    
    /**
     Schedules credentials rotation to begin.
     */
    public func start(roleSessionName: String?) {
        guard updateOnStart() else {
            // nothing to do; already started
            return
        }
        
        // only actually need to start updating credentials if the
        // initial ones expire
        if let expiration = expiringCredentials.expiration {
            scheduleUpdateCredentials(beforeExpiration: expiration,
                                      roleSessionName: roleSessionName)
        }
    }
    
    /**
     Gracefully shuts down credentials rotation, letting any ongoing work complete..
     */
    public func stop() {
        if let completionHandlers = updateOnShutdownStart() {
            return handleCredentialRotationShutdown(completionHandlers: completionHandlers)
        }
    }
    
    /**
     Blocks until credential rotation has been shutdown and all completion handlers
     have been executed.
     */
    public func wait() {
        if !isShutdown() {
            shutdownDispatchGroup.wait()
        }
    }
    
    /**
     Blocks credential rotation has been shutdown and all completion handlers
     have been executed. The provided closure will be added to the list of
     completion handlers to be executed on shutdown. If the worker is already
     shutdown, the provided closure will be immediately executed.
     
     - Parameters:
        - onShutdown: the closure to be executed after the worker has been
                      fully shutdown.
     */
    public func waitUntilShutdownAndThen(onShutdown: @escaping () -> Void) throws {
        let handlerQueuedForFutureShutdownComplete = addShutdownHandler(onShutdown: onShutdown)

        if handlerQueuedForFutureShutdownComplete {
            shutdownDispatchGroup.wait()
        } else {
            // the worker is already shutdown, immediately call the handler
            onShutdown()
        }
    }
    
    internal func scheduleUpdateCredentials(beforeExpiration expiration: Date,
                                            roleSessionName: String?) {
        // create a deadline 5 minutes before the expiration
        let timeInterval = (expiration - expirationBufferSeconds).timeIntervalSinceNow
        let timeInternalInMinutes = timeInterval / 60
        
        let minutes: Int = Int(timeInternalInMinutes) % 60
        let hours: Int = Int(timeInternalInMinutes) / 60
        
        let deadline = DispatchTime.now() + .seconds(Int(timeInterval))
        
        let logEntryPrefix: String
        if let roleSessionName = roleSessionName {
            logEntryPrefix = "Credentials for session '\(roleSessionName)'"
        } else {
            logEntryPrefix = "Credentials"
        }
        
        // create a new worker that will update the credentials
        let newWorker = { [unowned self] in
            guard self.verifyWorkerNotCancelled() else {
                return
            }
            
            Log.verbose("\(logEntryPrefix) about to expire; rotating.")
            
            let expiration: Date?
            do {
                let expiringCredentials = try self.expiringCredentialsRetriever.get()
                
                self.expiringCredentials = expiringCredentials
                
                expiration = expiringCredentials.expiration
            } catch {
                let timeIntervalSinceNow =
                    self.expiringCredentials.expiration?.timeIntervalSinceNow ?? 0
                
                let retryDuration: Double
                let logPrefix = "\(logEntryPrefix) rotation failed."
                
                // if the expiry of the current credentials is still in the future
                if timeIntervalSinceNow > 0 {
                    // try again relatively soon (still within the 5 minute credentials
                    // expirary buffer) to get new credentials
                    retryDuration = self.validCredentialsRetrySeconds
                    
                    Log.warning("\(logPrefix) Credentials still valid. "
                        + "Attempting credentials refresh in 1 minute.")
                } else {
                    // at this point, we have tried multiple times to get new credentials
                    // something is quite wrong; try again in the future but at
                    // a reduced frequency
                    retryDuration = self.invalidCredentialsRetrySeconds
                    
                    Log.error("\(logPrefix) Credentials no longer valid. "
                        + "Attempting credentials refresh in 1 hour.")
                }
                
                expiration = Date(timeIntervalSinceNow: retryDuration)
            }
            
            // if there is an expiry, schedule a rotation
            if let expiration = expiration {
                self.scheduleUpdateCredentials(beforeExpiration: expiration,
                                               roleSessionName: roleSessionName)
            }
        }
        
        Log.info("\(logEntryPrefix) updated; rotation scheduled in \(hours) hours, \(minutes) minutes.")
        scheduler.asyncAfter(deadline: deadline, qos: .unspecified,
                             flags: [], execute: newWorker)
        
        pthread_mutex_lock(&statusMutex)
        defer { pthread_mutex_unlock(&statusMutex) }
        
        self.status = .running
        self.currentWorker = newWorker
    }
    
    
    
    
    
    
    
    
    private func handleCredentialRotationShutdown(completionHandlers: [() -> Void]) {
        Log.verbose("Starting shutdown of credential rotation.")
        // execute all the completion handlers
        completionHandlers.forEach { $0() }
        
        expiringCredentialsRetriever.close()
        expiringCredentialsRetriever.wait()

        // release any waiters for shutdown
        self.shutdownDispatchGroup.leave()
        
        Log.verbose("Finished shutdown of credential rotation.")
    }
    
    /**
     Updates the Lifecycle state on a start request.
     - Returns: if the start request should be acted upon (and credential rotation started).
                Will be false if credential rotation is already running, is shutting down or has completed shutting down.
     */
    private func updateOnStart() -> Bool {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        if case .initialized = state {
            state = .processing

            return true
        }

        return false
    }
    
    /**
     Updates the Lifecycle state on a shutdown request.
     - Returns: If the shutdownCompletionHandlers has been shutdown as the result of this call.
     */
    private func updateOnShutdownStart() -> Bool {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        let shutdown: Bool
        switch state {
        case .processing:
            state = .shuttingDown
            wasShutdown = false
        case .shuttingDown, .shutDown:
            // nothing to do; already shutting down or shutdown
            isNowShutdown = false
        case .initialized, .scheduled:
            state = .shutDown
            
            completionHandlers = shutdownCompletionHandlers
            shutdownCompletionHandlers = []
        }
        
        return completionHandlers
    }
    
    /**
     Updates the Lifecycle state to shutdown credential rotation is shutting down
     - Returns: If the shutdownCompletionHandlers has been shutdown as the result of this call.
     */
    private func updateShutdownIfShuttingDown() -> Bool {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        let completionHandlers: [() -> Void]?
        switch state {
        case .initialized, .processing, .scheduled:
            completionHandlers = nil
        case .shuttingDown, .shutDown:
            state = .shutDown
            
            completionHandlers = shutdownCompletionHandlers
            shutdownCompletionHandlers = []
        }

        return completionHandlers
    }
    
    /**
     Indicates if credential rotation is currently shutdown.
     - Returns: if credential rotation is currently shutdown.
     */
    private func isShutdown() -> Bool {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        if case .shutDown = state {
            return true
        }

        return false
    }
    
    private func updateOnScheduledStart() {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        switch state {
        case .initialized, .shuttingDown, .shutDown, .scheduled:
            break
        case .processing:
            state = .scheduled
        }
    }
    
    private func updateOnScheduledEnd() {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }

        switch state {
        case .initialized, .shuttingDown, .shutDown, .processing:
            break
        case .scheduled:
            state = .processing
        }
    }
}
