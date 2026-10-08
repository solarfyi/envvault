import { invoke } from "@tauri-apps/api/core";

export interface Stats {
  projects: number;
  environments: number;
  secrets: number;
  ssh_keys: number;
  unlocked: boolean;
}

export interface UiStatus {
  exists: boolean;
  unlocked: boolean;
  vault_path: string;
  stats: Stats | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  environments: number;
  secrets: number;
}

export interface Environment {
  id: string;
  project_id: string;
  name: string;
  created_at: string;
  updated_at: string;
  secrets: number;
}

export interface Secret {
  id: string;
  project_id: string;
  environment_id: string;
  name: string;
  secret_type: string;
  description: string;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface AuditEntry {
  time: string;
  action: string;
  resource: string;
  result: string;
}

export const api = {
  status: () => invoke<UiStatus>("status"),
  init: (password: string) => invoke<void>("init", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),

  listProjects: () => invoke<Project[]>("list_projects"),
  createProject: (name: string, description: string) =>
    invoke<Project>("create_project", { name, description }),
  deleteProject: (name: string) => invoke<void>("delete_project", { name }),

  listEnvironments: (project: string) =>
    invoke<Environment[]>("list_environments", { project }),
  createEnvironment: (project: string, name: string) =>
    invoke<Environment>("create_environment", { project, name }),

  listSecrets: (project: string, env: string) =>
    invoke<Secret[]>("list_secrets", { project, env }),
  setSecret: (s: {
    project: string;
    env: string;
    name: string;
    secret_type: string;
    description: string;
    value: string;
  }) => invoke<Secret>("set_secret", s),
  revealSecret: (project: string, env: string, name: string) =>
    invoke<string>("reveal_secret", { project, env, name }),
  deleteSecret: (project: string, env: string, name: string) =>
    invoke<void>("delete_secret", { project, env, name }),

  listAudit: (limit = 100) => invoke<AuditEntry[]>("list_audit", { limit }),
};
