import "./styles.css";
import { api, type AuditEntry, type Secret, type UiStatus } from "./api";

const app = document.getElementById("app")!;
let status: UiStatus;
let toastTimer: number | undefined;

type View =
  | { name: "dashboard" }
  | { name: "projects" }
  | { name: "project"; project: string }
  | { name: "secrets"; project: string; env: string }
  | { name: "audit" };

let view: View = { name: "dashboard" };

// ---------- tiny DOM helpers (no innerHTML: secret names are user data) -----

type Child = Node | string | null | undefined;
type Attrs = Record<string, unknown>;

function h(tag: "input", attrs?: Attrs, ...children: Child[]): HTMLInputElement;
function h(tag: "select", attrs?: Attrs, ...children: Child[]): HTMLSelectElement;
function h(tag: string, attrs?: Attrs, ...children: Child[]): HTMLElement;
function h(tag: string, attrs: Attrs = {}, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined) continue;
    if (key === "class") el.className = String(value);
    else if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value as EventListener);
    } else if (key === "text") el.textContent = String(value);
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    el.append(child instanceof Node ? child : document.createTextNode(child));
  }
  return el;
}

function toast(message: string) {
  let el = document.getElementById("toast");
  if (!el) {
    el = h("div", { id: "toast" });
    document.body.append(el);
  }
  el.textContent = message;
  el.classList.add("show");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el?.classList.remove("show"), 3200);
}

function timeOf(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function dateOf(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

function relative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return iso;
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
  return dateOf(iso);
}

// ---------- lock screen ------------------------------------------------------

function renderLock(mode: "unlock" | "create") {
  const password = h("input", { type: "password", placeholder: "Master password", required: "true" });
  const confirm = h("input", { type: "password", placeholder: "Confirm master password" });
  const error = h("div", { class: "error" });
  const submit = h("button", { class: "btn primary", type: "submit" }, mode === "create" ? "Create vault" : "Unlock");

  const form = h(
    "form",
    {
      onsubmit: async (e: Event) => {
        e.preventDefault();
        error.textContent = "";
        submit.setAttribute("disabled", "true");
        try {
          if (mode === "create") {
            if (password.value !== confirm.value) throw new Error("passwords do not match");
            await api.init(password.value);
          } else {
            await api.unlock(password.value);
          }
          await boot();
        } catch (err) {
          error.textContent = String(err);
          password.value = "";
          confirm.value = "";
          password.focus();
        } finally {
          submit.removeAttribute("disabled");
        }
      },
    },
    h("label", { class: "field" }, h("span", {}, "Master Password"), password),
    mode === "create" ? h("label", { class: "field" }, h("span", {}, "Confirm Password"), confirm) : null,
    submit,
    error,
  );

  app.replaceChildren(
    h(
      "div",
      { class: "lock" },
      h(
        "div",
        { class: "box" },
        h("div", { class: "logo" }, "◈"),
        h("h1", {}, "ENVVAULT"),
        h(
          "div",
          { class: "state" },
          mode === "create" ? "Create your encrypted vault" : "Vault Locked",
        ),
        form,
        mode === "create"
          ? h("div", { class: "subtle", style: "margin-top:16px;font-size:12px;text-align:center" },
              "Minimum 8 characters. There is no password recovery.")
          : null,
      ),
    ),
  );
}

// ---------- shell ------------------------------------------------------------

function navItem(label: string, target: View, current: View) {
  const active = current.name === target.name ||
    (target.name === "projects" && (current.name === "project" || current.name === "secrets"));
  return h(
    "button",
    {
      class: `item${active ? " active" : ""}`,
      onclick: () => {
        view = target;
        void render();
      },
    },
    label,
  );
}

function shell(content: Node): Node {
  const unlocked = status.unlocked;
  return h(
    "div",
    { class: "shell" },
    h("div", { class: "brand" }, "ENVVAULT"),
    h(
      "div",
      { class: "header" },
      h("span", { class: "vault-path" }, status.vault_path),
      h(
        "span",
        { class: "status-pill" },
        h("span", { class: `status-dot${unlocked ? "" : " locked"}` }),
        unlocked ? "Vault Unlocked" : "Vault Locked",
      ),
    ),
    h(
      "nav",
      { class: "sidebar" },
      h("div", { class: "group" }, "OVERVIEW"),
      navItem("Dashboard", { name: "dashboard" }, view),
      h("div", { class: "group" }, "PROJECTS"),
      navItem("Projects", { name: "projects" }, view),
      h("div", { class: "group" }, "SECURITY"),
      navItem("Audit Log", { name: "audit" }, view),
      h("div", { class: "spacer" }),
      h(
        "button",
        {
          class: "item",
          onclick: async () => {
            await api.lock();
            view = { name: "dashboard" };
            await boot();
          },
        },
        "Lock vault",
      ),
    ),
    h("main", { class: "main" }, content),
    h(
      "div",
      { class: "footer" },
      h("span", {}, "EnvVault v0.1.0"),
      h("span", {}, "localhost / local"),
    ),
  );
}

// ---------- views ------------------------------------------------------------

async function renderDashboard(): Promise<Node> {
  const stats = status.stats ?? { projects: 0, environments: 0, secrets: 0, ssh_keys: 0, unlocked: false };
  let entries: AuditEntry[] = [];
  try {
    entries = await api.listAudit(8);
  } catch {
    entries = [];
  }

  const activity = entries.length
    ? h(
        "div",
        { class: "activity" },
        ...entries.map((e) =>
          h(
            "div",
            { class: "row" },
            h("span", { class: "time" }, timeOf(e.time)),
            h("span", { text: `${e.action}${e.resource ? ` — ${e.resource}` : ""}` }),
          ),
        ),
      )
    : h("div", { class: "empty" }, "No activity yet.");

  return h(
    "div",
    {},
    h("div", { class: "page-title" }, h("h1", {}, "Dashboard")),
    h(
      "div",
      { class: "cards" },
      h("div", { class: "card" }, h("div", { class: "label" }, "Projects"), h("div", { class: "value" }, String(stats.projects))),
      h("div", { class: "card" }, h("div", { class: "label" }, "Secrets"), h("div", { class: "value" }, String(stats.secrets))),
      h("div", { class: "card" }, h("div", { class: "label" }, "Environments"), h("div", { class: "value" }, String(stats.environments))),
      h(
        "div",
        { class: "card" },
        h("div", { class: "label" }, "Vault"),
        h("div", { class: "value small" }, h("span", { class: "status-dot", style: "display:inline-block;margin-right:8px" }), status.unlocked ? "Unlocked" : "Locked"),
      ),
    ),
    h(
      "div",
      { class: "panel" },
      h("div", { class: "panel-head" }, "Recent Activity"),
      activity,
    ),
  );
}

function newProjectModal() {
  const name = h("input", { type: "text", placeholder: "my-api", required: "true" });
  const description = h("input", { type: "text", placeholder: "Optional description" });
  const error = h("div", { class: "error" });

  openModal(
    "New Project",
    h(
      "div",
      {},
      h("label", { class: "field" }, h("span", {}, "NAME"), name),
      h("label", { class: "field" }, h("span", {}, "DESCRIPTION"), description),
      error,
    ),
    [
      { label: "Cancel", onClick: closeModal },
      {
        label: "Create",
        primary: true,
        onClick: async () => {
          try {
            const project = await api.createProject(name.value.trim(), description.value.trim());
            closeModal();
            view = { name: "project", project: project.name };
            await render();
            toast(`Project '${project.name}' created.`);
          } catch (err) {
            error.textContent = String(err);
          }
        },
      },
    ],
  );
  name.focus();
}

async function renderProjects(): Promise<Node> {
  const projects = await api.listProjects();
  const search = h("input", { type: "search", placeholder: "Search projects..." });

  const tbody = h("tbody");
  const draw = () => {
    const query = search.value.toLowerCase();
    const filtered = projects.filter((p) => p.name.toLowerCase().includes(query));
    tbody.replaceChildren(
      ...filtered.map((p) =>
        h(
          "tr",
          {
            onclick: () => {
              view = { name: "project", project: p.name };
              void render();
            },
          },
          h("td", {}, p.name),
          h("td", { class: "mono" }, String(p.environments)),
          h("td", { class: "mono" }, String(p.secrets)),
          h("td", {}, h("span", { class: "badge ok" }, "Active")),
        ),
      ),
      ...(filtered.length
        ? []
        : [h("tr", {}, h("td", { colspan: "4", class: "empty" }, "No projects found."))]),
    );
  };
  search.addEventListener("input", draw);
  draw();

  return h(
    "div",
    {},
    h(
      "div",
      { class: "page-title" },
      h("h1", {}, "Projects"),
      h("button", { class: "btn primary", onclick: newProjectModal }, "+ New Project"),
    ),
    h("div", { class: "toolbar" }, search),
    h(
      "div",
      { class: "panel" },
      h(
        "table",
        {},
        h(
          "thead",
          {},
          h(
            "tr",
            {},
            h("th", {}, "Project"),
            h("th", {}, "Environments"),
            h("th", {}, "Secrets"),
            h("th", {}, "Status"),
          ),
        ),
        tbody,
      ),
    ),
  );
}

async function renderProject(projectName: string): Promise<Node> {
  const project = await api.listProjects().then((list) => list.find((p) => p.name === projectName));
  const environments = await api.listEnvironments(projectName);

  const newEnvModal = () => {
    const name = h("input", { type: "text", placeholder: "staging", required: "true" });
    const error = h("div", { class: "error" });
    openModal(
      "New Environment",
      h("div", {}, h("label", { class: "field" }, h("span", {}, "NAME"), name), error),
      [
        { label: "Cancel", onClick: closeModal },
        {
          label: "Create",
          primary: true,
          onClick: async () => {
            try {
              await api.createEnvironment(projectName, name.value.trim());
              closeModal();
              await render();
              toast("Environment created.");
            } catch (err) {
              error.textContent = String(err);
            }
          },
        },
      ],
    );
    name.focus();
  };

  return h(
    "div",
    {},
    h(
      "div",
      { class: "crumb", onclick: () => { view = { name: "projects" }; void render(); } },
      "← Projects",
    ),
    h(
      "div",
      { class: "page-title" },
      h("h1", {}, projectName),
      h(
        "div",
        { style: "display:flex;gap:10px" },
        h("button", { class: "btn", onclick: newEnvModal }, "+ New Environment"),
        h(
          "button",
          {
            class: "btn danger",
            onclick: async () => {
              if (!window.confirm(`Delete project '${projectName}' and all its secrets?`)) return;
              await api.deleteProject(projectName);
              view = { name: "projects" };
              await render();
              toast("Project deleted.");
            },
          },
          "Delete",
        ),
      ),
    ),
    project?.description ? h("p", { class: "subtle", style: "margin-top:-8px" }, project.description) : null,
    h("h3", { style: "margin:18px 0 12px;font-size:14px;letter-spacing:.08em;color:var(--muted)" }, "ENVIRONMENTS"),
    environments.length
      ? h(
          "div",
          {},
          ...environments.map((env) =>
            h(
              "div",
              { class: "env-card" },
              h(
                "div",
                {},
                h("h3", {}, env.name),
                h(
                  "div",
                  { class: "meta" },
                  `${env.secrets} var${env.secrets === 1 ? "" : "s"} · modified ${relative(env.updated_at)}`,
                ),
              ),
              h(
                "div",
                { style: "display:flex;gap:10px;align-items:center" },
                h("span", { class: "badge ok" }, "Ready"),
                h(
                  "button",
                  {
                    class: "btn",
                    onclick: () => {
                      view = { name: "secrets", project: projectName, env: env.name };
                      void render();
                    },
                  },
                  "Open",
                ),
              ),
            ),
          ),
        )
      : h(
          "div",
          { class: "empty panel" },
          "No environments yet. Create one with: ",
          h("span", { class: "mono" }, `envvault env create ${projectName} development`),
        ),
  );
}

function addSecretModal(projectName: string, envName: string) {
  const name = h("input", { type: "text", placeholder: "API_KEY", required: "true" });
  const type = h(
    "select",
    {},
    ...["api-key", "database", "variable", "secret", "token"].map((t) => h("option", { value: t }, t)),
  );
  const value = h("input", { type: "password", placeholder: "••••••••••••", required: "true" });
  const description = h("input", { type: "text", placeholder: "OpenAI API authentication key" });
  const error = h("div", { class: "error" });

  openModal(
    "Add Secret",
    h(
      "div",
      {},
      h("label", { class: "field" }, h("span", {}, "NAME"), name),
      h("label", { class: "field" }, h("span", {}, "TYPE"), type),
      h("label", { class: "field" }, h("span", {}, "VALUE"), value),
      h("label", { class: "field" }, h("span", {}, "ENVIRONMENT"), h("input", { type: "text", value: envName, disabled: "true" })),
      h("label", { class: "field" }, h("span", {}, "DESCRIPTION"), description),
      error,
    ),
    [
      { label: "Cancel", onClick: closeModal },
      {
        label: "Save",
        primary: true,
        onClick: async () => {
          try {
            await api.setSecret({
              project: projectName,
              env: envName,
              name: name.value.trim(),
              secret_type: type.value,
              description: description.value.trim(),
              value: value.value,
            });
            closeModal();
            await render();
            toast("Secret saved.");
          } catch (err) {
            error.textContent = String(err);
          }
        },
      },
    ],
  );
  name.focus();
}

function secretModal(projectName: string, envName: string, secret: Secret) {
  const valueBox = h("div", { class: "value-box" }, "•••••••••••••••••••••••••");
  let revealed = false;

  const reveal = async () => {
    try {
      const value = await api.revealSecret(projectName, envName, secret.name);
      valueBox.textContent = value;
      valueBox.classList.add("revealed");
      revealed = true;
      toast("Revealed — this action was audited.");
    } catch (err) {
      toast(String(err));
    }
  };

  const copy = async () => {
    try {
      if (!revealed) await reveal();
      await navigator.clipboard.writeText(valueBox.textContent ?? "");
      toast("Copied — clipboard will clear in 20 seconds.");
      window.setTimeout(() => {
        void navigator.clipboard.writeText("").catch(() => undefined);
      }, 20000);
    } catch (err) {
      toast(String(err));
    }
  };

  openModal(
    secret.name,
    h(
      "div",
      {},
      h("div", { class: "subtle", style: "margin-bottom:12px" }, `Type: ${secret.secret_type}`),
      h("div", { class: "subtle", style: "margin-bottom:6px;font-size:12px" }, "VALUE"),
      valueBox,
      h(
        "div",
        { class: "kv" },
        h("span", { class: "k" }, "Created"),
        h("span", {}, dateOf(secret.created_at)),
        h("span", { class: "k" }, "Modified"),
        h("span", {}, dateOf(secret.updated_at)),
        h("span", { class: "k" }, "Version"),
        h("span", { class: "mono" }, String(secret.version)),
      ),
      h("div", { class: "warning" }, "⚠ Revealing this secret will be audited."),
    ),
    [
      {
        label: "Delete",
        danger: true,
        onClick: async () => {
          if (!window.confirm(`Delete secret '${secret.name}'?`)) return;
          await api.deleteSecret(projectName, envName, secret.name);
          closeModal();
          await render();
          toast("Secret deleted.");
        },
      },
      { label: "Copy", onClick: copy },
      { label: "Reveal", primary: true, onClick: reveal },
    ],
  );
}

async function renderSecrets(projectName: string, envName: string): Promise<Node> {
  const secrets = await api.listSecrets(projectName, envName);
  const search = h("input", { type: "search", placeholder: "Search secrets..." });
  const tbody = h("tbody");

  const draw = () => {
    const query = search.value.toLowerCase();
    const filtered = secrets.filter((s) => s.name.toLowerCase().includes(query));
    tbody.replaceChildren(
      ...filtered.map((s) =>
        h(
          "tr",
          { onclick: () => secretModal(projectName, envName, s) },
          h("td", { class: "mono" }, s.name),
          h("td", {}, s.secret_type),
          h("td", { class: "subtle" }, relative(s.updated_at)),
          h("td", { class: "dots" }, "••••••••••••"),
        ),
      ),
      ...(filtered.length
        ? []
        : [h("tr", {}, h("td", { colspan: "4", class: "empty" }, "No secrets in this environment."))]),
    );
  };
  search.addEventListener("input", draw);
  draw();

  return h(
    "div",
    {},
    h(
      "div",
      {
        class: "crumb",
        onclick: () => {
          view = { name: "project", project: projectName };
          void render();
        },
      },
      "←",
      projectName,
      "/",
      envName,
    ),
    h(
      "div",
      { class: "page-title" },
      h("h1", {}, "Secrets"),
      h("button", { class: "btn primary", onclick: () => addSecretModal(projectName, envName) }, "+ Add Secret"),
    ),
    h("div", { class: "toolbar" }, search),
    h(
      "div",
      { class: "panel" },
      h(
        "table",
        {},
        h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Type"), h("th", {}, "Updated"), h("th", {}, "Value"))),
        tbody,
      ),
    ),
  );
}

async function renderAudit(): Promise<Node> {
  const entries = await api.listAudit(200);
  return h(
    "div",
    {},
    h(
      "div",
      { class: "page-title" },
      h("h1", {}, "Audit Log"),
      h("span", { class: "subtle" }, "Secret values are never recorded."),
    ),
    h(
      "div",
      { class: "panel" },
      h(
        "table",
        {},
        h(
          "thead",
          {},
          h("tr", {}, h("th", {}, "Time"), h("th", {}, "Action"), h("th", {}, "Resource"), h("th", {}, "Result")),
        ),
        h(
          "tbody",
          {},
          ...(entries.length
            ? entries.map((e) =>
                h(
                  "tr",
                  {},
                  h("td", { class: "mono" }, `${timeOf(e.time)}`),
                  h("td", {}, e.action),
                  h("td", { class: "mono subtle" }, e.resource || "—"),
                  h(
                    "td",
                    {},
                    h("span", { class: `badge ${e.result === "success" ? "ok" : "fail"}` }, e.result),
                  ),
                ),
              )
            : [h("tr", {}, h("td", { colspan: "4", class: "empty" }, "Audit log is empty."))]),
        ),
      ),
    ),
  );
}

// ---------- modal ------------------------------------------------------------

interface ModalButton {
  label: string;
  onClick: () => void | Promise<void>;
  primary?: boolean;
  danger?: boolean;
}

function openModal(title: string, body: Node, buttons: ModalButton[]) {
  const overlay = h("div", {
    class: "overlay",
    onclick: (e: Event) => {
      if (e.target === overlay) closeModal();
    },
  });
  overlay.append(
    h(
      "div",
      { class: "modal" },
      h(
        "div",
        { class: "modal-head" },
        title,
        h("button", { class: "close", onclick: closeModal }, "×"),
      ),
      h("div", { class: "modal-body" }, body),
      h(
        "div",
        { class: "modal-foot" },
        ...buttons.map((b) =>
          h(
            "button",
            {
              class: `btn${b.primary ? " primary" : ""}${b.danger ? " danger" : ""}`,
              onclick: () => void b.onClick(),
            },
            b.label,
          ),
        ),
      ),
    ),
  );
  document.body.append(overlay);
}

function closeModal() {
  document.querySelector(".overlay")?.remove();
}

// ---------- bootstrap --------------------------------------------------------

async function render() {
  const content = await (async () => {
    switch (view.name) {
      case "dashboard":
        return renderDashboard();
      case "projects":
        return renderProjects();
      case "project":
        return renderProject(view.project);
      case "secrets":
        return renderSecrets(view.project, view.env);
      case "audit":
        return renderAudit();
    }
  })();
  app.replaceChildren(shell(content));
}

async function boot() {
  status = await api.status();
  if (!status.exists) {
    renderLock("create");
    return;
  }
  if (!status.unlocked) {
    renderLock("unlock");
    return;
  }
  await render();
}

void boot().catch((err) => {
  app.replaceChildren(h("div", { class: "empty" }, `Failed to start: ${String(err)}`));
});
