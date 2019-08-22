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
//  AwsContainerRotatingCredentials+get.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeAWSCore
import Logging
import SmokeHTTPClient

public typealias AwsContainerRotatingCredentialsProvider = AwsRotatingCredentialsProvider

public extension AwsContainerRotatingCredentialsProvider {
    // the endpoint for obtaining credentials from the ECS container
    // https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
    private static let credentialsHost = "169.254.170.2"
    private static let credentialsPort = 80
    
    /**
     The Environment variable that can be passed in conjunction with
     the DEBUG compiler flag to gain credentials based on the
     IAM Role ARN specified.
 
     If this Environment variable and the DEBUG compiler flag are specified,
     this class will first attempt to obtain credentials from the container
     environment and then static credentials under the AWS_SECRET_ACCESS_KEY
     and AWS_ACCESS_KEY_ID keys. If neither are present, this class will call
     the shell script-
       /usr/local/bin/get-credentials.sh -r <role> -d <role lifetype>
     
     This script should write to its standard output a JSON structure capable of
     being decoded into the ExpiringCredentials structure.
     */
    static let devIamRoleArnEnvironmentVariable = "DEV_CREDENTIALS_IAM_ROLE_ARN"
 
    /**
     Static function that retrieves credentials provider from the specified environment -
     either rotating credentials retrieved from an endpoint specified under the
     AWS_CONTAINER_CREDENTIALS_RELATIVE_URI key or if that key isn't present,
     static credentials under the AWS_SECRET_ACCESS_KEY and AWS_ACCESS_KEY_ID keys.
     */
    static func get(fromEnvironment environment: [String: String] = ProcessInfo.processInfo.environment,
                    reporting: SmokeAWSInvocationReporting,
                    eventLoopProvider: HTTPClient.EventLoopProvider = .spawnNewThreads)
        -> StoppableCredentialsProvider? {
            let dataRetrieverProvider: (String) -> () throws -> Data = { credentialsPath in
                return {
                    guard let response = try BasicChannelInboundHandler.call(
                        endpointHostName: credentialsHost,
                        endpointPath: credentialsPath,
                        reporting: reporting,
                        eventLoopProvider: eventLoopProvider,
                        endpointPort: credentialsPort) else {
                            let reason = "Unable to retrieve credentials: No credentials returned from endpoint"
                                + " '\(credentialsHost):\(credentialsPort)/\(credentialsPath)'."
                            throw SmokeAWSCredentialsError.missingCredentials(reason: reason)
                    }
                    
                    return response
                }
            }
            
            return get(fromEnvironment: environment, reporting: reporting,
                       dataRetrieverProvider: dataRetrieverProvider)
    }
    
    /**
     Internal static function for testing.
     */
    static func get(fromEnvironment environment: [String: String],
                    reporting: SmokeAWSInvocationReporting,
                    dataRetrieverProvider: (String) -> () throws -> Data)
        -> StoppableCredentialsProvider? {
            var credentialsProvider: StoppableCredentialsProvider?
            if let rotatingCredentials = getRotatingCredentialsProvider(
                fromEnvironment: environment, reporting: reporting,
                dataRetrieverProvider: dataRetrieverProvider) {
                    credentialsProvider = rotatingCredentials
            }
            
            if credentialsProvider == nil,
                let staticCredentials = getStaticCredentialsProvider(
                    fromEnvironment: environment, reporting: reporting,
                    dataRetrieverProvider: dataRetrieverProvider) {
                        credentialsProvider = staticCredentials
            }
            
            #if DEBUG
            if credentialsProvider == nil,
                let rotatingCredentials = getDevRotatingCredentialsProvider(fromEnvironment: environment, reporting: reporting) {
                    credentialsProvider = rotatingCredentials
            }
            #endif
            
            return credentialsProvider
    }
    
    private static func getStaticCredentialsProvider(
        fromEnvironment environment: [String: String],
        reporting: SmokeAWSInvocationReporting,
        dataRetrieverProvider: (String) -> () throws -> Data)
        -> StoppableCredentialsProvider? {
            // get the values of the environment variables
            let awsAccessKeyId = environment["AWS_ACCESS_KEY_ID"]
            let awsSecretAccessKey = environment["AWS_SECRET_ACCESS_KEY"]
            let sessionToken = environment["AWS_SESSION_TOKEN"]
            
            guard let secretAccessKey = awsSecretAccessKey, let accessKeyId = awsAccessKeyId else {
                reporting.logger.info(
                    "'AWS_ACCESS_KEY_ID' and 'AWS_SESSION_TOKEN' environment variables not specified. Static credentials not available.")
                
                return nil
            }
            
            reporting.logger.debug("Static credentials retrieved from environment.")
            
            // return these credentials
            return SmokeAWSCore.StaticCredentials(accessKeyId: accessKeyId,
                                                  secretAccessKey: secretAccessKey,
                                                  sessionToken: sessionToken)
    }
    
#if DEBUG
    private static func getDevRotatingCredentialsProvider(fromEnvironment environment: [String: String],
                                                          reporting: SmokeAWSInvocationReporting) -> StoppableCredentialsProvider? {
        // get the values of the environment variables
        let devCredentialsIamRoleArn = environment["DEV_CREDENTIALS_IAM_ROLE_ARN"]
        
        guard let iamRoleArn = devCredentialsIamRoleArn else {
            reporting.logger.info("'DEV_CREDENTIALS_IAM_ROLE_ARN' environment variable not specified. Dev rotating credentials not available.")
            
            return nil
        }
        
        let dataRetriever: () throws -> Data = {
            let outputPipe = Pipe()
            
            let task = Process()
            task.launchPath = "/usr/bin/env"
            task.arguments = ["/usr/local/bin/get-credentials.sh",
                              "-r",
                              iamRoleArn,
                              "-d",
                              "900"]
            task.standardOutput = outputPipe
            task.launch()
            task.waitUntilExit()

            return outputPipe.fileHandleForReading.availableData
        }
        
        let rotatingCredentialsProvider: StoppableCredentialsProvider
        do {
            rotatingCredentialsProvider = try createRotatingCredentialsProvider(reporting: reporting, dataRetriever: dataRetriever)
        } catch {
            reporting.logger.error("Retrieving dev rotating credentials rotation failed: '\(error)'")
            
            return nil
        }
        
        return rotatingCredentialsProvider
    }
#endif
    
    private static func getRotatingCredentialsProvider(
        fromEnvironment environment: [String: String],
        reporting: SmokeAWSInvocationReporting,
        dataRetrieverProvider: (String) -> () throws -> Data)
        -> StoppableCredentialsProvider? {
        // get the values of the environment variables
        let awsContainerCredentialsRelativeUri = environment["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
        
        guard let credentialsPath = awsContainerCredentialsRelativeUri else {
            reporting.logger.info("'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' environment variable not specified. Rotating credentials not available.")
            
            return nil
        }
        
        let dataRetriever = dataRetrieverProvider(credentialsPath)
        let rotatingCredentialsProvider: StoppableCredentialsProvider
        do {
            rotatingCredentialsProvider = try createRotatingCredentialsProvider(
                reporting: reporting, dataRetriever: dataRetriever)
        } catch {
            reporting.logger.error("Retrieving rotating credentials rotation failed: '\(error)'")
            
            return nil
        }
        
        return rotatingCredentialsProvider
    }
    
    private static func createRotatingCredentialsProvider(
        reporting: SmokeAWSInvocationReporting,
        dataRetriever: @escaping () throws -> Data) throws
        -> StoppableCredentialsProvider {
        let credentialsRetriever = FromDataExpiringCredentialsRetriever(
            dataRetriever: dataRetriever)
            
        let awsContainerRotatingCredentialsProvider =
            try AwsContainerRotatingCredentialsProvider(
                expiringCredentialsRetriever: credentialsRetriever, reporting: reporting)
        
        awsContainerRotatingCredentialsProvider.start(
            roleSessionName: nil)
        
        reporting.logger.debug("Rotating credentials retrieved from environment.")
        
        // return the credentials
        return awsContainerRotatingCredentialsProvider
    }
    
    internal struct FromDataExpiringCredentialsRetriever: ExpiringCredentialsRetriever {
        let dataRetriever: () throws -> Data
        
        func close() {
            // nothing to do
        }
        
        func wait() {
            // nothing to do
        }
        
        func get() throws -> ExpiringCredentials {
            return try ExpiringCredentials.getCurrentCredentials(
                    dataRetriever: dataRetriever)
        }
    }
}
