import type { Capability, TaintLabel } from "@arikernel/core";
import { ToolCallDeniedError } from "@arikernel/core";
import { type Firewall, createFirewall } from "@arikernel/runtime";

export interface SessionConfig {
	principal: string;
	capabilities: Capability[];
}

interface Session {
	id: string;
	firewall: Firewall;
	lastActivity: number;
}

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

export class SessionManager {
	private sessions = new Map<string, Session>();
	private timer: ReturnType<typeof setInterval>;
	private policyPath: string;
	private auditPath: string;

	constructor(policyPath: string, auditPath: string) {
		this.policyPath = policyPath;
		this.auditPath = auditPath;
		this.timer = setInterval(() => this.reapExpired(), 60_000);
	}

	create(config: SessionConfig): { sessionId: string; runId: string } {
		const firewall = createFirewall({
			principal: {
				name: config.principal,
				capabilities: config.capabilities,
			},
			policies: this.policyPath,
			auditLog: this.auditPath,
		});

		const sessionId = firewall.runId;
		this.sessions.set(sessionId, {
			id: sessionId,
			firewall,
			lastActivity: Date.now(),
		});

		return { sessionId, runId: firewall.runId };
	}

	get(sessionId: string): Firewall | null {
		const session = this.sessions.get(sessionId);
		if (!session) return null;
		session.lastActivity = Date.now();
		return session.firewall;
	}

	destroy(sessionId: string): boolean {
		const session = this.sessions.get(sessionId);
		if (!session) return false;
		session.firewall.close();
		this.sessions.delete(sessionId);
		return true;
	}

	private reapExpired(): void {
		const cutoff = Date.now() - SESSION_TTL_MS;
		for (const [id, session] of this.sessions) {
			if (session.lastActivity < cutoff) {
				session.firewall.close();
				this.sessions.delete(id);
			}
		}
	}

	close(): void {
		clearInterval(this.timer);
		for (const [id, session] of this.sessions) {
			session.firewall.close();
			this.sessions.delete(id);
		}
	}
}
