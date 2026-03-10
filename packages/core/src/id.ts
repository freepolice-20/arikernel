import { ulid } from "ulid";

export function generateId(): string {
	return ulid();
}

export function now(): string {
	return new Date().toISOString();
}
