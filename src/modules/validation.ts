import * as z from 'zod'
import { Either, PT, RulesError } from './types'
import { isLeft, makeLeft, makeRight, unwrapEither } from './utils'
import { Address, checksumAddress, isAddress } from 'viem'

/**
 * Creates lookup maps for efficient calling function resolution.
 * This utility function creates the necessary Map structures for O(1) lookups.
 *
 * @param callingFunctions - Array of calling function definitions
 * @returns Object containing the three lookup maps
 */
export const createCallingFunctionLookupMaps = (callingFunctions: CallingFunctionJSON[]) => {
  // Policy names must never resolve through Object.prototype.
  const callingFunctionByName: Record<string, CallingFunctionJSON> = Object.create(null)
  const callingFunctionBySignature: Record<string, CallingFunctionJSON> = Object.create(null)
  const callingFunctionByNameLower: Record<string, CallingFunctionJSON> = Object.create(null)

  // Pre-populate lookup maps for efficient resolution using reduce
  callingFunctions.reduce(
    (maps, cf) => {
      maps.byName[cf.Name] = cf
      maps.byNameLower[cf.Name.toLowerCase()] = cf
      if (cf.FunctionSignature && cf.FunctionSignature !== cf.Name) {
        maps.bySignature[cf.FunctionSignature] = cf
      }
      return maps
    },
    {
      byName: callingFunctionByName,
      byNameLower: callingFunctionByNameLower,
      bySignature: callingFunctionBySignature,
    }
  )

  return { callingFunctionByName, callingFunctionBySignature, callingFunctionByNameLower }
}

/**
 * Validates that a calling function exists by name in the lookup maps.
 * This function checks if the referenced calling function name exists in the defined calling functions.
 *
 * @param callingFunctionRef - The calling function name to validate
 * @param lookupMaps - The pre-built lookup maps for efficient resolution
 * @throws Error with descriptive message if calling function is not found
 */
export const validateCallingFunctionExists = (
  callingFunctionRef: string,
  lookupMaps: {
    callingFunctionByName: Record<string, CallingFunctionJSON>
    callingFunctionBySignature: Record<string, CallingFunctionJSON>
    callingFunctionByNameLower: Record<string, CallingFunctionJSON>
  }
): void => {
  const { callingFunctionByName } = lookupMaps

  // Check if the calling function exists by name
  if (!Object.hasOwn(callingFunctionByName, callingFunctionRef)) {
    const availableFunctions = Object.keys(callingFunctionByName)
    throw new Error(
      `Calling function "${callingFunctionRef}" not found. ` +
        `Available calling functions: ${
          availableFunctions.length > 0 ? availableFunctions.join(', ') : 'none defined'
        }. ` +
        `Please ensure the calling function is defined in the CallingFunctions array before referencing it in rules or foreign calls.`
    )
  }
}

/**
 * Resolves calling function name to full signature using lookup maps.
 * Supports backward compatibility by accepting both name-only references and full signatures.
 * Uses O(1) Map lookups for optimal performance.
 *
 * @param callingFunctionRef - Either a short name or full function signature
 * @param lookupMaps - The pre-built lookup maps for efficient resolution
 * @returns The resolved function signature or the original reference if not found
 */
export const resolveCallingFunction = (
  callingFunctionRef: string,
  lookupMaps: {
    callingFunctionByName: Record<string, CallingFunctionJSON>
    callingFunctionBySignature: Record<string, CallingFunctionJSON>
    callingFunctionByNameLower: Record<string, CallingFunctionJSON>
  }
): string => {
  const { callingFunctionByName, callingFunctionBySignature, callingFunctionByNameLower } = lookupMaps

  // First check if it's already a full signature (contains parentheses)
  if (callingFunctionRef.includes('(')) {
    return callingFunctionRef
  }

  // Try to find by name field (exact match) - O(1)
  const foundByName = Object.hasOwn(callingFunctionByName, callingFunctionRef)
    ? callingFunctionByName[callingFunctionRef]
    : undefined
  if (foundByName) {
    return foundByName.FunctionSignature || foundByName.Name
  }

  // Try case-insensitive name match - O(1)
  const foundByNameIgnoreCase = Object.hasOwn(callingFunctionByNameLower, callingFunctionRef.toLowerCase())
    ? callingFunctionByNameLower[callingFunctionRef.toLowerCase()]
    : undefined
  if (foundByNameIgnoreCase) {
    return foundByNameIgnoreCase.FunctionSignature || foundByNameIgnoreCase.Name
  }

  // Try to find by functionSignature field - O(1)
  const foundBySignature = Object.hasOwn(callingFunctionBySignature, callingFunctionRef)
    ? callingFunctionBySignature[callingFunctionRef]
    : undefined
  if (foundBySignature) {
    return foundBySignature.FunctionSignature || foundBySignature.Name
  }

  // Return as-is if not found (will be validated elsewhere)
  return callingFunctionRef
}

const EMPTY_STRING = ''
/**
 * Accepts any input, if input is a string, it trims whitespace from both ends.
 * if input is not a string the input is returned as is.
 *
 * @param input - value to be trimmed if it is a string.
 * @returns The trimmed input or the original input if not a string.
 */
const trimPossibleString = (input: unknown): unknown => {
  if (typeof input === 'string') {
    return input.trim()
  } else {
    return input
  }
}

/**
 * Parses a JSON string and returns Either a successful result or an error.
 *
 * @param input - string to be parsed.
 * @returns Either the parsed string or an error.
 */
export const safeParseJson = (input: string): Either<RulesError[], object> => {
  try {
    const result = JSON.parse(input)
    return makeRight(result)
  } catch (error) {
    return makeLeft([
      {
        errorType: 'INPUT',
        state: { input },
        message: 'Failed to parse JSON',
      },
    ])
  }
}

export const PType = PT.map((p) => p.name) // ["address", "string", "uint256", "bool", "void", "bytes"]

export const splitFunctionInput = (input: string): string[] => {
  const params = input?.split('(')[1]?.split(')')[0]?.trim() || ''
  // Return empty array for empty parameters instead of array with empty string
  return params === '' ? [] : params.split(',').map((p) => p.trim())
}

/**
 * Accepts an array of RulesError objects and returns a formatted message string
 *
 * @param errors - RulesErrors array to be processed.
 * @returns The errors messages concatenated into a single string
 */
export const getRulesErrorMessages = (errors: RulesError[]): string => {
  return errors.map((err) => `${err.message}`).join('\n')
}

const validateLogicalOperatorGroup = (operator: string, condition: string[]): boolean =>
  condition.join(' ').split(operator).length == 2

/**
 * Accepts an array of RulesError objects and returns a formatted message string
 *
 * @param condition - A condition group represented as an array of strings.
 * @returns boolean, true if the groups 3 terms and 1 is AND or OR, false otherwise.
 */
export const validateConditionGroup = (condition: string[]): boolean => {
  const andOperator = 'AND'
  const orOperator = 'OR'

  const andTerms = validateLogicalOperatorGroup(andOperator, condition)
  const orTerms = validateLogicalOperatorGroup(orOperator, condition)

  return andTerms || orTerms
}

const validateInputReferencedCalls = (
  foreignCallNames: string[],
  trackerNames: string[],
  mappedTrackerNames: string[],
  input: string
): boolean => {
  const fcRegex = /FC:[a-zA-Z]+[^\s]+/g
  const trRegex = /(TR|TRU):[a-zA-Z]+ /g
  const trMappedRegex = /(TR|TRU):[a-zA-Z]+\([^()]+\)/g

  const fcMatches = input.match(fcRegex) || []
  const trMatches = input.match(trRegex) || []
  const trMappedMatches = input.match(trMappedRegex) || []

  const [mappedTrackers, mappedTrackerParams] = trMappedMatches.reduce(
    (acc: [string[], string[]], match) => {
      const [name, params] = match.split('(')
      acc[0].push(name.replace(/^(TR|TRU):/, '').trim())
      acc[1].push(params.replace(')', '').trim())
      return acc
    },
    [[], []]
  )
  let validateForeignCalls = true
  if (fcMatches.length > 0)
    validateForeignCalls =
      foreignCallNames !== undefined
        ? fcMatches.every((match) => foreignCallNames.includes(match.replace('FC:', '').trim()))
        : false
  const validateTrackers = trMatches.every((match) => trackerNames.includes(match.replace(/^(TR|TRU):/, '').trim()))
  const validateMappedTrackers = mappedTrackers.every((match) => mappedTrackerNames.includes(match))

  return validateForeignCalls && validateTrackers && validateMappedTrackers
}

const validateValuesToPass = (
  callingFunctionEncodedValues: string[],
  foreignCallNames: string[],
  trackerNames: string[],
  mappedTrackerNames: string[],
  valuesToPass: string
): boolean => {
  // Handle empty valuesToPass - this is valid for functions with no parameters
  if (valuesToPass.trim() === '') {
    return true
  }

  return valuesToPass
    .split(',')
    .map((value) => {
      value = value.trim()
      if (value.startsWith('FC:')) {
        return foreignCallNames.includes(value.replace('FC:', '').trim())
      } else if (value.startsWith('GV:')) {
        // Validate global variables - check against supported list
        const globalVar = value.replace('GV:', '').trim()
        const supportedGlobalVars = ['MSG_SENDER', 'BLOCK_TIMESTAMP', 'MSG_DATA', 'BLOCK_NUMBER', 'TX_ORIGIN']
        return supportedGlobalVars.includes(globalVar)
      } else if (value.startsWith('TR:') || value.startsWith('TRU:')) {
        value = value.replace(/^(TR|TRU):/, '').trim()
        if (value.includes('(')) {
          value = value.split('(')[0].trim()
          return mappedTrackerNames.includes(value)
        } else {
          return trackerNames.includes(value)
        }
      } else if (callingFunctionEncodedValues.includes(value)) {
        return true // If it is a calling function value, it is valid
      }
      return false
    })
    .every((isValid) => isValid)
}

/**
 * Validates that all foreign calls and rules reference existing calling functions
 * @param input - The policy JSON object (may be merged with existing policy data)
 * @returns boolean indicating if all references are valid
 */
const validateReferencedCalls = (input: any): boolean => {
  // Early return if no calling functions defined
  if (!input.CallingFunctions || input.CallingFunctions.length === 0) {
    return (input.ForeignCalls?.length ?? 0) === 0 && (input.Rules?.length ?? 0) === 0
  }
  const callingFunctionNames = input.CallingFunctions.map((call: CallingFunctionJSON) => call.Name)
  const callingFunctionSignatures = input.CallingFunctions.map(
    (call: CallingFunctionJSON) => call.FunctionSignature || call.Name
  )
  const fcCallingFunctions: string[] = input.ForeignCalls?.map((fc: any) => fc.CallingFunction) ?? []

  // Allow foreign calls to reference either the name or the full signature
  if (
    !fcCallingFunctions.every(
      (fcName) => callingFunctionNames.includes(fcName) || callingFunctionSignatures.includes(fcName)
    )
  ) {
    return false
  }

  return true
}

export const ruleValidator = z.object({
  Id: z.coerce.number().optional(),
  Name: z.string().default(EMPTY_STRING),
  Description: z.string().default(EMPTY_STRING),
  Condition: z.string(),
  PositiveEffects: z.array(z.string()),
  NegativeEffects: z.array(z.string()),
  CallingFunction: z.string(),
})
export interface RuleJSON extends z.infer<typeof ruleValidator> {}

/**
 * Parses a JSON string and returns Either a RuleJSON object or an error.
 *
 * @param rule - string to be parsed.
 * @returns Either the parsed RuleJSON object or an error.
 */
export const validateRuleJSON = (rule: string): Either<RulesError[], RuleJSON> => {
  const parsedJson = safeParseJson(rule)

  if (isLeft(parsedJson)) return parsedJson

  const parsed = ruleValidator.safeParse(unwrapEither(parsedJson))

  if (parsed.success) {
    return makeRight(parsed.data)
  } else {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Rule ${err.message}: Field ${err.path.join('.')}`,
      state: { input: rule },
    }))
    return makeLeft(errors)
  }
}

/**
 * Validates foreign call parameters to ensure they are of supported types.
 *
 * @param input - string to be validated.
 * @returns true if input is valid, false if input is invalid.
 */
export const validateFCFunctionInput = (input: string): boolean => {
  // Detect presence of parentheses; if missing, params are undefined => invalid
  const signature = /^([a-zA-Z_$][a-zA-Z0-9_$]*)\(([^()]*)\)$/.exec(input.trim())
  if (!signature) return false

  // Extract inner params
  const inner = signature[2].trim()
  // Empty string means zero parameters => valid
  if (inner === '') return true

  // Otherwise, validate each declared type against supported PType list
  const parts = inner
    .split(',')
    .map((p) => p.trim())
  return parts.every((parameter) => (PType as string[]).includes(parameter))
}

export const foreignCallValidator = z.object({
  Id: z.coerce.number().optional(),
  Name: z.string(),
  Function: z.string().trim().refine(validateFCFunctionInput, { message: 'Unsupported argument type' }),
  Address: z
    .string()
    .trim()
    .refine((input) => isAddress(input), {
      message: `Address is invalid`,
    })
    .transform((input) => checksumAddress(input.trim() as Address)),
  ReturnType: z.preprocess(trimPossibleString, z.literal(PType, 'Unsupported return type')),
  ValuesToPass: z
    .string()
    .trim()
    .refine(
      (valuesToPass) => {
        // Check if any GV: parameters are valid
        const params = valuesToPass.split(',').map((p) => p.trim())
        const supportedGlobalVars = ['MSG_SENDER', 'BLOCK_TIMESTAMP', 'MSG_DATA', 'BLOCK_NUMBER', 'TX_ORIGIN']

        for (const param of params) {
          if (param.startsWith('GV:')) {
            const globalVar = param.replace('GV:', '').trim()
            if (!supportedGlobalVars.includes(globalVar)) {
              return false
            }
          }
        }
        return true
      },
      {
        message:
          'Unsupported global variable in ValuesToPass. Supported: GV:MSG_SENDER, GV:BLOCK_TIMESTAMP, GV:MSG_DATA, GV:BLOCK_NUMBER, GV:TX_ORIGIN',
      }
    ),
  MappedTrackerKeyValues: z.string().trim(),
  CallingFunction: z.string().trim(),
})

export interface ForeignCallJSON extends z.infer<typeof foreignCallValidator> {}

/**
 * Parses a JSON string and returns Either a ForeignCallJSON object or an error.
 *
 * @param foreignCall - string to be parsed.
 * @returns Either the parsed ForeignCallJSON object or an error.
 */
export const validateForeignCallJSON = (foreignCall: string): Either<RulesError[], ForeignCallJSON> => {
  const parsedJson = safeParseJson(foreignCall)

  if (isLeft(parsedJson)) return parsedJson

  const parsed = foreignCallValidator.safeParse(unwrapEither(parsedJson))

  if (parsed.success) {
    return makeRight(parsed.data)
  } else {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Foreign Call ${err.message}: Field ${err.path.join('.')}`,
      state: { input: foreignCall },
    }))
    return makeLeft(errors)
  }
}

export const foreignCallReverseValidator = foreignCallValidator.extend({
  function: z.string().trim(),
})

export interface ForeignCallJSONReversed extends z.infer<typeof foreignCallValidator> {}

export const paramTypes = PT.map((p) => p.name)
export type ParameterTypes = (typeof paramTypes)[number]
export const supportedTrackerTypes = paramTypes.filter((name) => name !== 'void')

export type SupportedTrackers = (typeof supportedTrackerTypes)[number]

export const supportedTrackerKeyTypes = supportedTrackerTypes.filter((t) => !t.includes('[]'))

export type SupportedTrackerKeys = (typeof supportedTrackerKeyTypes)[number]

/**
 * Validates tracker initial value to ensure it matches the type specified.
 *
 * @param type - type of value to be validated.
 * @param value - value to be validated.
 * @returns true if input is valid, false if input is invalid.
 */
const validateTrackerValue = (type: SupportedTrackers, value: unknown): boolean => {
  // Validate that the initialValue matches the type
  switch (type) {
    case 'uint256': {
      // Validate the integer text before conversion to avoid precision loss and coercion.
      if (typeof value !== 'string' || !/^(?:[0-9]+|0x[0-9a-fA-F]+)$/.test(value)) return false
      return BigInt(value) < (1n << 256n)
    }
    case 'string':
      return typeof value === 'string'
    case 'address':
      return typeof value === 'string' && isAddress(value)
    case 'bytes':
      return typeof value === 'string' // The parser encodes bytes from UTF-8 text.
    case 'bool':
      return value === 'true' || value === 'false'
    default:
      return false // Unsupported type
  }
}

const validateTrackerInitialValue = (data: any): boolean => {
  if (data.Type.includes('[]')) {
    // For arrays, we assume initialValue is an array of values
    if (!Array.isArray(data.InitialValue)) {
      return false // Initial value must be an array for array types
    }
    return data.InitialValue.every((value: any) => validateTrackerValue(data.Type.replace('[]', ''), value))
  } else {
    // For non-array types, we validate the single initialValue
    return validateTrackerValue(data.Type, data.InitialValue)
  }
}

const validateMappedTrackerInitialInputs = (type: any, inputs: any): boolean => {
  if (!Array.isArray(inputs)) {
    return false // Initial values must be an array for array types
  }
  if (type.includes('[]')) {
    return inputs.every(
      (value: any) => Array.isArray(value) && value.every((v: any) => validateTrackerValue(type.replace('[]', ''), v))
    )
  } else {
    return inputs.every((value: any) => validateTrackerValue(type, value))
  }
}

const validateMappedTrackerInitialValues = (data: any): boolean => {
  return validateMappedTrackerInitialInputs(data.ValueType, data.InitialValues)
}

const validateMappedTrackerInitialKeys = (data: any): boolean => {
  return validateMappedTrackerInitialInputs(data.KeyType, data.InitialKeys)
}

const validateMappedTrackerInitialLengths = (data: any): boolean => {
  return data.InitialKeys.length === data.InitialValues.length
}

const validateUniqueKeys = <T>(keys: T[]): boolean => {
  const uniqueKeys = new Set(keys)
  return uniqueKeys.size === keys.length
}

const validateMappedTrackerUniqueKeys = (data: any): boolean => {
  return validateUniqueKeys(data.InitialKeys)
}

export const trackerValidator = z
  .object({
    Id: z.coerce.number().optional(),
    Name: z.string().trim(),
    Type: z.preprocess(trimPossibleString, z.literal(supportedTrackerTypes, 'Unsupported type')),
    InitialValue: z.union([z.string().trim(), z.array(z.string().trim())]),
  })
  .refine(validateTrackerInitialValue, {
    message: "Initial Value doesn't match type",
  })

export interface TrackerJSON extends z.infer<typeof trackerValidator> {}

export interface MappedTrackerJSON extends z.infer<typeof mappedTrackerValidator> {}

export const mappedTrackerValidator = z
  .object({
    Id: z.coerce.number().optional(),
    Name: z.string().trim(),
    KeyType: z.preprocess(trimPossibleString, z.literal(supportedTrackerKeyTypes, 'Unsupported key type')),
    ValueType: z.preprocess(trimPossibleString, z.literal(supportedTrackerTypes, 'Unsupported type')),
    InitialKeys: z.array(z.string()),
    InitialValues: z.array(z.union([z.string().trim(), z.array(z.string().trim())])),
  })
  .refine(validateMappedTrackerInitialValues, {
    message: 'Mapped Tracker Initial Values do not match type',
  })
  .refine(validateMappedTrackerInitialKeys, {
    message: 'Mapped Tracker Initial Keys do not match type',
  })
  .refine(validateMappedTrackerInitialLengths, {
    message: 'Mapped Tracker Initial Keys and Values must have the same length',
  })
  .refine(validateMappedTrackerUniqueKeys, {
    message: 'Mapped Tracker Initial Keys must be unique',
  })

/**
 * Parses a JSON string and returns Either a TrackerJSON object or an error.
 *
 * @param tracker - string to be parsed.
 * @returns Either the parsed TrackerJSON object or an error.
 */
export const validateTrackerJSON = (tracker: string): Either<RulesError[], TrackerJSON> => {
  const parsedJson = safeParseJson(tracker)
  if (isLeft(parsedJson)) return parsedJson
  const parsed = trackerValidator.safeParse(unwrapEither(parsedJson))
  if (parsed.success) {
    return makeRight(parsed.data)
  } else {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Tracker ${err.message}: Field ${err.path.join('.')}`,
      state: { input: tracker },
    }))
    return makeLeft(errors)
  }
}

/**
 * Parses a JSON string and returns Either a MappedTrackerJSON object or an error.
 *
 * @param tracker - string to be parsed.
 * @returns Either the parsed MappedTrackerJSON object or an error.
 */
export const validateMappedTrackerJSON = (tracker: string): Either<RulesError[], MappedTrackerJSON> => {
  const parsedJson = safeParseJson(tracker)

  if (isLeft(parsedJson)) return parsedJson

  const parsed = mappedTrackerValidator.safeParse(unwrapEither(parsedJson))

  if (parsed.success) {
    return makeRight(parsed.data)
  } else {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Mapped Tracker ${err.message}: Field ${err.path.join('.')}`,
      state: { input: tracker },
    }))
    return makeLeft(errors)
  }
}

export const callingFunctionValidator = z.object({
  Name: z.string().trim(),
  FunctionSignature: z.string().trim(),
  EncodedValues: z.string().trim(),
})

export interface CallingFunctionJSON extends z.infer<typeof callingFunctionValidator> {}

/**
 * Parses a JSON string and returns Either a CallingFunctionJSON object or an error.
 *
 * @param callingFunction - string to be parsed.
 * @returns Either the parsed CallingFunctionJSON object or an error.
 */
export const validateCallingFunctionJSON = (callingFunction: string): Either<RulesError[], CallingFunctionJSON> => {
  const parsedJson = safeParseJson(callingFunction)
  if (isLeft(parsedJson)) return parsedJson
  const parsed = callingFunctionValidator.safeParse(unwrapEither(parsedJson))
  if (parsed.success) {
    return makeRight(parsed.data)
  } else {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Calling Function${err.message}: Field ${err.path.join('.')}`,
      state: { input: callingFunction },
    }))
    return makeLeft(errors)
  }
}

const groupFCByCallingFunction = (acc: Record<string, string[]>, fc: any) => {
  const callingFunction = fc.CallingFunction
  if (!acc[callingFunction]) {
    acc[callingFunction] = [fc.Name]
  } else {
    acc[callingFunction].push(fc.Name)
  }
  return acc
}

const validateUniqueNames = (input: any): boolean => {
  const trackerKeys = input.Trackers.map((tracker: any) => tracker.Name)
  const mappedTrackerKeys = input.MappedTrackers.map((tracker: any) => tracker.Name)
  const callingFunctions = input.CallingFunctions.map((fn: any) => fn.Name)

  const foreignCalls = input.ForeignCalls.reduce(groupFCByCallingFunction, {})

  return [trackerKeys, mappedTrackerKeys, callingFunctions, ...Object.values(foreignCalls)]
    .map(validateUniqueKeys)
    .every((isValid) => isValid)
}

export const policyJSONValidator = z
  .object({
    Id: z.coerce.number().optional(),
    Policy: z.string().default(EMPTY_STRING),
    Description: z.string().default(EMPTY_STRING),
    PolicyType: z.string(),
    CallingFunctions: z.array(callingFunctionValidator),
    ForeignCalls: z.array(foreignCallValidator),
    Trackers: z.array(trackerValidator),
    MappedTrackers: z.array(mappedTrackerValidator),
    Rules: z.array(ruleValidator),
  })
  .refine(validateUniqueNames, { message: 'Names cannot be duplicated' })
  .refine(
    (data) => {
      const rulesWithIds = data.Rules.filter((rule) => rule.Id != null)
      let ids: (number | bigint)[] = rulesWithIds.map((rule) => rule.Id!)
      if (!validateUniqueKeys(ids)) {
        return false
      }

      const fcWithIds = data.ForeignCalls.filter((fc) => fc.Id != null)
      ids = fcWithIds.map((fc) => fc.Id!)
      if (!validateUniqueKeys(ids)) {
        return false
      }

      const trackersWithIds = data.Trackers.filter((tracker) => tracker.Id != null)
      ids = trackersWithIds.map((tracker) => tracker.Id!)
      if (!validateUniqueKeys(ids)) {
        return false
      }

      const mappedTrackersWithIds = data.MappedTrackers.filter((tracker) => tracker.Id != null)
      ids = mappedTrackersWithIds.map((tracker) => tracker.Id!)
      if (!validateUniqueKeys(ids)) {
        return false
      }

      return true
    },
    {
      message: 'Id validation failed: only one instance of each Id is allowed per component within a policy.',
    }
  )

export interface PolicyJSON extends z.infer<typeof policyJSONValidator> {}

/**
 * Parses a JSON string and returns Either a PolicyJSON object or an error.
 *
 * @param policy - string to be parsed.
 * @param existingPolicy - optional existing policy data to merge with for update operations.
 * @returns Either the parsed PolicyJSON object or an error.
 */
export const validatePolicyJSON = (policy: string, existingPolicy?: PolicyJSON): Either<RulesError[], PolicyJSON> => {
  const parsedJson = safeParseJson(policy)

  if (isLeft(parsedJson)) return parsedJson

  const originalPolicyData: any = unwrapEither(parsedJson)

  // First, validate the structure of the original input (without reference checks)
  const parsed = policyJSONValidator.safeParse(originalPolicyData)

  if (!parsed.success) {
    const errors: RulesError[] = parsed.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Policy ${err.message}${err.path.length ? `: Field ${err.path.join('.')}` : ''}`,
      state: { input: policy },
    }))
    return makeLeft(errors)
  }

  // If we have an existing policy, merge it with the input data for reference validation
  // This allows validation during updates where the input may only contain new/updated entities
  let mergedPolicyData: any = originalPolicyData
  if (existingPolicy) {
    mergedPolicyData = {
      Id: originalPolicyData.Id ?? existingPolicy.Id,
      Policy: originalPolicyData.Policy ?? existingPolicy.Policy,
      Description: originalPolicyData.Description ?? existingPolicy.Description,
      PolicyType: originalPolicyData.PolicyType ?? existingPolicy.PolicyType,
      // Merge arrays: combine existing entities with new/updated ones
      // Use a Map to handle updates by Name for efficient merging
      CallingFunctions: mergeEntitiesByName(existingPolicy.CallingFunctions, originalPolicyData.CallingFunctions || []),
      ForeignCalls: mergeEntitiesByName(existingPolicy.ForeignCalls, originalPolicyData.ForeignCalls || []),
      Trackers: mergeEntitiesByName(existingPolicy.Trackers, originalPolicyData.Trackers || []),
      MappedTrackers: mergeEntitiesByName(existingPolicy.MappedTrackers, originalPolicyData.MappedTrackers || []),
      Rules: mergeEntitiesByName(existingPolicy.Rules, originalPolicyData.Rules || []),
    }
  }

  // Perform reference validation on the merged data (which has full context)
  const referenceCheck = policyJSONValidator
    .refine(validateReferencedCalls, { message: 'Invalid reference call' })
    .safeParse(mergedPolicyData)

  if (!referenceCheck.success) {
    const errors: RulesError[] = referenceCheck.error.issues.map((err) => ({
      errorType: 'INPUT',
      message: `Policy ${err.message}${err.path.length ? `: Field ${err.path.join('.')}` : ''}`,
      state: { input: policy },
    }))
    return makeLeft(errors)
  }

  // Both validations passed - return the original input data (not the merged version)
  return makeRight(parsed.data)
}

/**
 * Merges existing entities with new entities, prioritizing new entities by Name.
 * This is used during policy updates to combine on-chain state with update input.
 *
 * @param existing - Array of existing entities from on-chain state
 * @param updates - Array of new/updated entities from input
 * @returns Merged array with updates taking precedence
 */
const mergeEntitiesByName = <T extends { Name: string }>(existing: T[], updates: T[]): T[] => {
  // Create a map of existing entities by name
  const entityMap = new Map<string, T>()

  // Add all existing entities
  existing.forEach((entity) => entityMap.set(entity.Name, entity))

  // Override with updates (new or updated entities)
  updates.forEach((entity) => entityMap.set(entity.Name, entity))

  return Array.from(entityMap.values())
}
