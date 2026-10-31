/// SPDX-License-Identifier: BUSL-1.1
import * as fs from 'fs'
import * as path from 'path'
import { generateModifier } from './generate-solidity'
import { injectModifier } from './inject-modifier'
import { getRulesErrorMessages, validatePolicyJSON } from '../modules/validation'
import { isLeft, unwrapEither } from '../modules/utils'

/**
 * Validates a list of file paths to ensure they exist and have .sol extension
 * @param filePaths Array of file paths to validate
 * @returns Array of valid Solidity file paths
 */
function validateSolidityFiles(filePaths: string[]): string[] {
  const validFiles: string[] = []

  for (const filePath of filePaths) {
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.warn(`Warning: File does not exist: ${filePath}`)
      continue
    }

    // Check if file has .sol extension
    if (path.extname(filePath).toLowerCase() !== '.sol') {
      console.warn(`Warning: File is not a Solidity file: ${filePath}`)
      continue
    }

    validFiles.push(filePath)
  }

  return validFiles
}

/**
 * Checks if a file contains a specific calling function
 * @param filePath Path to the file to check
 * @param callingFunction signature of the calling function to look for
 * @returns True if the calling function is found in the file
 */
function fileContainsFunction(filePath: string, callingFunction: string): boolean {
  const fileContent = fs.readFileSync(filePath, 'utf-8')

  // Since callingFunction is now just the function name, use it directly
  const functionName = callingFunction.trim()

  // Create a regex pattern that looks for the function name followed by parameters
  // This is a simplified approach and might need refinement for complex cases
  const regexPattern = `function\\s+${functionName}\\s*\\([^)]*\\)`
  const regex = new RegExp(regexPattern, 'i')

  return regex.test(fileContent)
}

/**
 * Processes a policy configuration file and injects modifiers into matching Solidity files
 * @param configPath Path to the policy JSON configuration file
 * @param outputFile The directory and name of the file to create for the modifiers
 * @param filePaths Array of Solidity file paths to process
 */
export function policyModifierGeneration(configPath: string, outputFile: string, filePaths: string[]): void {
  // Validate Solidity files
  const validFiles = validateSolidityFiles(filePaths)
  if (validFiles.length === 0) {
    console.error('Error: No valid Solidity files provided')
    return
  }

  console.log(`Found ${validFiles.length} valid Solidity files to process ${configPath}`)

  // Read and parse the policy configuration
  const configData = fs.readFileSync(configPath, 'utf-8')
  console.log(`Reading policy configuration from ${configPath} - ${Buffer.byteLength(configData, 'utf-8')} bytes`)
  const policyJson = validatePolicyJSON(configData)
  if (isLeft(policyJson)) {
    throw new Error(getRulesErrorMessages(policyJson.left))
  }
  const policyConfig = unwrapEither(policyJson)

  console.log(`Processing policy: ${policyConfig.Policy}`)
  console.log(`Found ${policyConfig.Rules.length} rules to process`)

  generateModifier(configData, outputFile)
  console.log(`Generated modifier and saved to ${outputFile}`)
  // Process each rule
  policyConfig.Rules.forEach((rule, index) => {
    // Since rule.callingFunction is now just the function name, use it directly
    const functionName = rule.CallingFunction.trim()

    // Find files that contain the calling function and inject the modifier
    let injectionCount = 0
    for (const filePath of validFiles) {
      if (fileContainsFunction(filePath, rule.CallingFunction)) {
        console.log(`Found matching function in ${filePath}`)
        const encodedValues = policyConfig.CallingFunctions.find((cf) => cf.Name === functionName)?.EncodedValues || ''

        // Inject the modifier (without creating a diff file)
        injectModifier(
          functionName,
          encodedValues,
          filePath,
          'diff.diff', // Empty string means no diff file will be created
          outputFile
        )

        injectionCount++
      }
    }

    if (injectionCount === 0) {
      console.warn(`Warning: No files found containing function ${rule.CallingFunction}`)
    } else {
      console.log(`Injected modifier for ${functionName} into ${injectionCount} files`)
    }
  })

  console.log('Policy processing complete!')
}
