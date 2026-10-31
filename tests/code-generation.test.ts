/// SPDX-License-Identifier: BUSL-1.1
import { expect, test } from 'vitest'
import { generateModifier } from '../src/codeGeneration/generate-solidity'
import {
  addModifierToFunctionDeclarations,
  contractHasSecurityOverride,
  injectModifier,
} from '../src/codeGeneration/inject-modifier'
import * as fs from 'fs'
import { policyModifierGeneration } from '../src/codeGeneration/code-modification-script'

test('Code Modification test)', () => {
  // Test that the existing UserContract.sol has the expected modifier
  const data = fs.readFileSync('tests/testOutput/UserContract.sol', 'utf-8')
  expect(data.includes('checkRulesBeforetransfer(')).toBeTruthy()
})

test('Code Generation test)', () => {
  const policyJSON = `
        {
        "Policy": "Test Policy",
        "Description": "Test Policy Description",
        "PolicyType": "open",
        "CallingFunctions": [
            {
              "Name": "transfer",
              "FunctionSignature": "transfer(address to, uint256 value)",
              "EncodedValues": "address to, uint256 value"
            }
        ],
        "ForeignCalls": [
            {
                "Name": "Simple Foreign Call",
                "Address": "0xa5cc3c03994DB5b0d9A5eEdD10CabaB0813678AC",
                "Function": "testSig(address)",
                "ReturnType": "uint256",
                "ValuesToPass": "to",
                "MappedTrackerKeyValues": "",
                "CallingFunction": "transfer"
            }
        ], 
        "Trackers": [
        {
            "Name": "Simple String Tracker",
            "Type": "string",
            "InitialValue": "test" 
        }
        ],
        "MappedTrackers": [],
        "Rules": [
            {
                "Name": "Rule A",
                "Description": "Rule A Description",
                "Condition": "value > 500",
                "PositiveEffects": ["emit Success"],
                "NegativeEffects": ["revert()"],
                "CallingFunction": "transfer"
            }
        ]
        }`

  generateModifier(policyJSON, 'tests/testOutput/testFileA.sol')
  injectModifier(
    'transfer',
    'address to, uint256 value, uint256 somethingElse',
    'tests/testOutput/UserContract.sol',
    'tests/testOutput/diff.diff',
    'tests/testOutput/testFileA.sol'
  )
  expect(fs.existsSync('tests/testOutput/diff.diff')).toBeTruthy()
  expect(fs.existsSync('tests/testOutput/testFileA.sol')).toBeTruthy()

  fs.readFile('tests/testOutput/UserContract.sol', 'utf-8', (err, data) => {
    if (err) {
      console.error('Error reading file:', err)
      return
    }

    expect(data.includes('checkRulesBeforetransfer(')).toBeTruthy()

    expect(data.includes('setCallingContractAdmin(')).toBeTruthy()
  })
})

test('Security override detection', () => {
  const singleLineDeclaration = 'function setCallingContractAdmin(address callingContractAdmin) public {}'
  const multiLineDeclaration = `function setCallingContractAdmin(address callingContractAdmin) public {
  }`

  const singleLineDetected = contractHasSecurityOverride(singleLineDeclaration)
  const multiLineDetected = contractHasSecurityOverride(multiLineDeclaration)
  const noDeclarationDetected = contractHasSecurityOverride('function someOtherFunction() public {}')

  expect(singleLineDetected).toBe(true)
  expect(multiLineDetected).toBe(true)
  expect(noDeclarationDetected).toBe(false)
})

test('Inject rules modifier into calling function', () => {
  const contractData = `
  /// SPDX-License-Identifier: BUSL-1.1
  pragma solidity ^0.8.24;

  contract ExampleUserContract {
      function transfer(address to, uint256 value, uint256 publicValue) public publicFoo() {
      }
  }
`
  const UPDATED_DECLARATION = `function transfer(address to, uint256 value, uint256 publicValue) public checkRulesBeforetransfer(to, value, somethingElse) publicFoo() {`

  const updatedContract = addModifierToFunctionDeclarations(
    contractData,
    'function',
    'transfer',
    'checkRulesBeforetransfer(to, value, somethingElse)'
  )
  expect(updatedContract.includes(UPDATED_DECLARATION)).toBe(true)
})

test('Inject rules modifier into calling function visibility last', () => {
  const contractData = `
  /// SPDX-License-Identifier: BUSL-1.1
  pragma solidity ^0.8.24;

  contract ExampleUserContract {
      function transfer(address to, uint256 value, uint256 publicValue) publicFoo() public {}
  }
`
  const UPDATED_DECLARATION = `function transfer(address to, uint256 value, uint256 publicValue) publicFoo() public checkRulesBeforetransfer(to, value, somethingElse) {`

  const updatedContract = addModifierToFunctionDeclarations(
    contractData,
    'function',
    'transfer',
    'checkRulesBeforetransfer(to, value, somethingElse)'
  )
  expect(updatedContract.includes(UPDATED_DECLARATION)).toBe(true)
})

test('Inject rules modifier into calling function no space between visibility modifier and {', () => {
  const contractData = `
  /// SPDX-License-Identifier: BUSL-1.1
  pragma solidity ^0.8.24;

  contract ExampleUserContract {
      function transfer(address to, uint256 value, uint256 publicValue) publicFoo() public{}
  }
`
  const UPDATED_DECLARATION = `function transfer(address to, uint256 value, uint256 publicValue) publicFoo() public checkRulesBeforetransfer(to, value, somethingElse) {`

  const updatedContract = addModifierToFunctionDeclarations(
    contractData,
    'function',
    'transfer',
    'checkRulesBeforetransfer(to, value, somethingElse)'
  )
  expect(updatedContract.includes(UPDATED_DECLARATION)).toBe(true)
})
