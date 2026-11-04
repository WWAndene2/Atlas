// Validates graph records against the JSON Schemas in schema/, the public contract with every agent.
import { readFileSync } from "node:fs";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import { repositoryPath } from "./repository-path.js";
import type { Evidence, GraphEdge, GraphNode, Hypothesis } from "./model.js";

// ajv-formats is CommonJS: under NodeNext its default import is the module object.
const addFormats = addFormatsModule as unknown as (ajv: Ajv2020) => Ajv2020;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

function compile(file: string): ValidateFunction {
  return ajv.compile(JSON.parse(readFileSync(repositoryPath("schema", file), "utf8")) as object);
}

const validators = {
  node: compile("node.schema.json"),
  edge: compile("edge.schema.json"),
  evidence: compile("evidence.schema.json"),
  hypothesis: compile("hypothesis.schema.json"),
};

export type RecordType = keyof typeof validators;

export class SchemaError extends Error {
  constructor(
    readonly recordType: RecordType,
    readonly details: string,
  ) {
    super(`invalid ${recordType}: ${details}`);
    this.name = "SchemaError";
  }
}

function assertValid(recordType: RecordType, value: unknown): void {
  const validate = validators[recordType];
  if (!validate(value)) {
    throw new SchemaError(recordType, ajv.errorsText(validate.errors));
  }
}

export function assertNode(value: unknown): asserts value is GraphNode {
  assertValid("node", value);
}

export function assertEdge(value: unknown): asserts value is GraphEdge {
  assertValid("edge", value);
}

export function assertEvidence(value: unknown): asserts value is Evidence {
  assertValid("evidence", value);
}

export function assertHypothesis(value: unknown): asserts value is Hypothesis {
  assertValid("hypothesis", value);
}
