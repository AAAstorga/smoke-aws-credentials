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
//  SmokeAWSCredentialsInvocationReporting.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeAWSCore
import Logging

internal struct SmokeAWSCredentialsInvocationReporting: SmokeAWSInvocationReporting {
    let logger: Logger
    
    internal static let awsContainerDefault: SmokeAWSInvocationReporting = {
        var logger = Logger(label: "com.amazon.SmokeAWSCredentials.provider.AwsContainer")
        logger[metadataKey: "credentialsProvider"] = "AwsContainer"
        
        return SmokeAWSCredentialsInvocationReporting(logger: logger)
    }()
    
    internal static func getAssumedRoleDefault(roleArn: String, roleSessionName: String) -> SmokeAWSInvocationReporting {
        var logger = Logger(label: "com.amazon.SmokeAWSCredentials.provider.\(roleSessionName)")
        logger[metadataKey: "credentialsProvider"] = "AwsContainer"
        logger[metadataKey: "roleArn"] = .string(roleArn)
        logger[metadataKey: "roleSessionName"] = .string(roleSessionName)
        
        return SmokeAWSCredentialsInvocationReporting(logger: logger)
    }
}
