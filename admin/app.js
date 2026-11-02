const $ = (id) => document.getElementById(id);
const roleNames = {
  server_admin: "Server administrator",
  organization_admin: "Organization administrator",
  manager: "Manager",
  member: "Member",
  user: "User",
};
let token = null,
  me = null,
  organizations = [],
  selected = null,
  snapshot = null,
  view = "overview",
  saving = false,
  dialogAction = null,
  dialogFocus = null,
  rendering = 0;
const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const notice = (message, error = false) => {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
};
function button(label, action, className) {
  const node = el("button", label, className);
  node.type = "button";
  node.addEventListener("click", async () => {
    if (saving) return;
    node.disabled = true;
    try {
      await action();
    } catch (error) {
      notice(error.message, true);
    } finally {
      node.disabled = false;
    }
  });
  return node;
}
async function api(path, method = "GET", body) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    if (response.status === 401 && token) signOut();
    const error = await response.json().catch(() => ({}));
    throw Error(error.message || `Request failed (${response.status}).`);
  }
  return response.status === 204 ? null : response.json();
}
function signOut() {
  token = null;
  me = null;
  organizations = [];
  snapshot = null;
  selected = null;
  rendering++;
  closeDialog(true);
  $("content").replaceChildren();
  $("organization").replaceChildren();
  $("identity").textContent = "";
  $("app-view").hidden = true;
  $("login-view").hidden = false;
  $("login-form").reset();
  $("login-form").elements.username.focus();
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget,
    submit = form.querySelector("button");
  submit.disabled = true;
  $("login-error").textContent = "";
  try {
    const session = await api("/auth/login", "POST", {
      username: form.elements.username.value,
      password: form.elements.password.value,
    });
    token = session.access_token;
    form.elements.password.value = "";
    me = await api("/auth/me");
    $("identity").textContent = `${me.username} · ${roleNames[me.role] || me.role}`;
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    await reloadOrganizations();
    await render();
  } catch (error) {
    $("login-error").textContent = error.message;
    form.elements.password.value = "";
    if (!me) token = null;
  } finally {
    submit.disabled = false;
  }
});
$("logout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", "POST");
  } finally {
    signOut();
  }
});
function orgAdmin() {
  return (
    me?.role === "server_admin" ||
    organizations.find((org) => org.id === selected)?.role === "organization_admin"
  );
}
async function reloadOrganizations() {
  organizations = await api("/organizations");
  if (!organizations.some((org) => org.id === selected)) selected = organizations[0]?.id || null;
  $("organization").replaceChildren(
    ...organizations.map((org) => {
      const option = el("option", org.name);
      option.value = org.id;
      return option;
    }),
  );
  if (!organizations.length) {
    const option = el("option", "No organizations");
    option.value = "";
    $("organization").append(option);
  }
  $("organization").value = selected || "";
  document.querySelector('[data-view="users"]').hidden = me.role !== "server_admin" && !orgAdmin();
  for (const name of ["members", "access"])
    document.querySelector(`[data-view="${name}"]`).hidden = !orgAdmin();
}
$("organization").addEventListener("change", async (event) => {
  selected = event.target.value || null;
  await reloadOrganizations();
  await render();
});
for (const node of document.querySelectorAll("[data-view]"))
  node.addEventListener("click", async () => {
    view = node.dataset.view;
    await render();
  });
function toolbar(description, action) {
  const bar = el("div", undefined, "toolbar");
  bar.append(el("p", description));
  if (action) bar.append(action);
  $("content").append(bar);
}
function table(headers, rows) {
  if (!rows.length) {
    const empty = el("div", undefined, "empty");
    empty.append(
      el("h2", "Nothing here yet"),
      el("p", "Create an item or ask your organization administrator for access."),
    );
    $("content").append(empty);
    return;
  }
  const wrap = el("div", undefined, "table-wrap"),
    table = el("table"),
    head = el("tr");
  for (const header of headers) head.append(el("th", header));
  const thead = el("thead");
  thead.append(head);
  table.append(thead);
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    for (const cell of row) {
      const td = el("td");
      td.append(cell instanceof Node ? cell : el("span", String(cell)));
      tr.append(td);
    }
    body.append(tr);
  }
  table.append(body);
  wrap.append(table);
  $("content").append(wrap);
}
function actions(...items) {
  const group = el("div", undefined, "actions");
  group.append(...items.filter(Boolean));
  return group;
}
function field(parent, label, value = "", type = "text") {
  const wrapper = el("label", label),
    input = el("input");
  input.type = type;
  input.value = value;
  input.autocomplete = "off";
  input.required = true;
  input.maxLength = type === "password" ? 1024 : 40;
  wrapper.append(input);
  parent.append(wrapper);
  return input;
}
function selectField(parent, label, items, current) {
  const wrapper = el("label", label),
    input = el("select");
  input.id = `select-${crypto.randomUUID()}`;
  wrapper.htmlFor = input.id;
  for (const [value, name] of items) {
    const option = el("option", name);
    option.value = value;
    input.append(option);
  }
  if (current !== undefined) input.value = current;
  parent.append(wrapper, input);
  return input;
}
function checkField(parent, label, checked) {
  const wrapper = el("label", undefined, "check"),
    input = el("input");
  input.type = "checkbox";
  input.checked = checked;
  wrapper.append(input, document.createTextNode(label));
  parent.append(wrapper);
  return input;
}
function openDialog(title, build, action, save = "Save changes") {
  dialogFocus = document.activeElement;
  $("dialog-title").textContent = title;
  $("fields").replaceChildren();
  $("dialog-error").textContent = "";
  $("save-dialog").textContent = save;
  dialogAction = action;
  $("save-dialog").disabled = false;
  build($("fields"));
  $("dialog").showModal();
  $("fields").querySelector("input,select,button")?.focus();
}
function closeDialog(force = false) {
  if (saving && !force) return;
  $("dialog").close();
  $("fields")
    .querySelectorAll("input")
    .forEach((input) => {
      input.value = "";
    });
  $("fields").replaceChildren();
  dialogAction = null;
  dialogFocus?.focus();
}
$("close-dialog").addEventListener("click", closeDialog);
$("cancel-dialog").addEventListener("click", closeDialog);
$("dialog").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeDialog();
});
$("editor").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (saving || !dialogAction) return;
  saving = true;
  $("dialog-error").textContent = "";
  const controls = [...$("editor").querySelectorAll("input,select,button")];
  const enabled = controls.filter((node) => !node.disabled);
  enabled.forEach((node) => {
    node.disabled = true;
  });
  try {
    await dialogAction();
    saving = false;
    closeDialog();
    if (!token) return;
    await reloadOrganizations();
    await render();
    notice("Changes saved.");
  } catch (error) {
    $("dialog-error").textContent = error.message;
  } finally {
    saving = false;
    enabled.forEach((node) => {
      node.disabled = false;
    });
  }
});
function confirmAction(title, message, action) {
  openDialog(title, (parent) => parent.append(el("p", message)), action, "Confirm");
}
function editOrganization(org) {
  let name;
  openDialog(
    org ? "Rename organization" : "Create organization",
    (parent) => {
      name = field(parent, "Organization name", org?.name || "");
    },
    () =>
      api(org ? `/organizations/${org.id}` : "/organizations", org ? "PUT" : "POST", {
        name: name.value,
      }),
  );
}
function createUser() {
  let username, password, role, admin;
  openDialog(
    "Create user",
    (parent) => {
      username = field(parent, "Username");
      username.maxLength = 64;
      password = field(parent, "Initial password", "", "password");
      password.minLength = 12;
      if (selected)
        role = selectField(
          parent,
          "Organization role",
          Object.entries(roleNames).filter(([key]) =>
            ["organization_admin", "manager", "member"].includes(key),
          ),
          "member",
        );
      if (me.role === "server_admin")
        admin = checkField(parent, "Server administrator (access to all organizations)", false);
      parent.append(
        el(
          "p",
          "Share the initial password through a trusted channel. The user can change it after signing in.",
        ),
      );
    },
    () =>
      api("/users", "POST", {
        username: username.value,
        password: password.value,
        server_admin: admin?.checked || false,
        organization_id: selected,
        role: role?.value || null,
      }),
  );
}
function editUser(user) {
  let disabled, admin, password;
  openDialog(
    `Manage ${user.username}`,
    (parent) => {
      disabled = checkField(parent, "Disable sign-in and revoke all sessions", user.disabled);
      admin = checkField(parent, "Server administrator", user.server_admin);
      password = field(parent, "Reset password (leave empty to keep it)", "", "password");
      password.required = false;
      password.minLength = 12;
      parent.append(el("p", "Saving security changes revokes this user's sessions."));
    },
    () =>
      api(`/users/${user.id}`, "PUT", {
        disabled: disabled.checked,
        server_admin: admin.checked,
        password: password.value || null,
      }),
  );
}
async function editMember(member) {
  let role, target;
  let candidates = [];
  if (!member && me.role === "server_admin") candidates = await api("/users");
  openDialog(
    member ? `Role · ${member.username}` : "Add existing user",
    (parent) => {
      if (!member) {
        if (candidates.length)
          target = selectField(
            parent,
            "User",
            candidates.map((user) => [user.id, user.username]),
          );
        else {
          target = field(parent, "User ID supplied by the server administrator");
          target.maxLength = 36;
        }
      }
      role = selectField(
        parent,
        "Organization role",
        [
          ["organization_admin", roleNames.organization_admin],
          ["manager", roleNames.manager],
          ["member", roleNames.member],
        ],
        member?.role || "member",
      );
      parent.append(
        el(
          "p",
          "Managers and members need an explicit workspace grant. Only organization administrators can change access.",
        ),
      );
    },
    () =>
      api(`/organizations/${selected}/members/${member?.user_id || target.value}`, "PUT", {
        role: role.value,
      }),
  );
}
function editWorkspace(workspace) {
  const document = workspace
    ? structuredClone(workspace.document)
    : { name: "", categories: [], channels: [] };
  let name;
  openDialog(
    workspace ? "Edit workspace" : "Create workspace",
    (parent) => {
      name = field(parent, "Workspace name", document.name);
      parent.append(
        el(
          "p",
          "This structure synchronizes to authorized desktop clients. WhatsApp profiles and messages stay on each computer.",
        ),
      );
      const categories = el("section", undefined, "document-section"),
        channels = el("section", undefined, "document-section");
      parent.append(categories, channels);
      function draw() {
        categories.replaceChildren(el("h3", "Categories"));
        for (const category of document.categories) {
          const row = el("div", undefined, "document-row"),
            input = el("input");
          input.value = category.name;
          input.required = true;
          input.maxLength = 40;
          input.setAttribute("aria-label", "Category name");
          input.addEventListener("input", () => {
            category.name = input.value;
          });
          row.append(
            input,
            el("span"),
            button("Remove", () => {
              document.categories = document.categories.filter((item) => item.id !== category.id);
              for (const channel of document.channels)
                if (channel.category_id === category.id) channel.category_id = null;
              draw();
            }),
          );
          categories.append(row);
        }
        const addCategory = button("Add category", () => {
          document.categories.push({
            id: crypto.randomUUID(),
            name: "New category",
          });
          draw();
        });
        addCategory.disabled = document.categories.length >= 40;
        categories.append(addCategory);
        channels.replaceChildren(el("h3", "Channels"));
        for (const channel of document.channels) {
          const row = el("div", undefined, "document-row"),
            input = el("input"),
            select = el("select");
          input.value = channel.name;
          input.required = true;
          input.maxLength = 40;
          input.setAttribute("aria-label", "Channel name");
          input.addEventListener("input", () => {
            channel.name = input.value;
          });
          for (const category of [{ id: "", name: "No category" }, ...document.categories]) {
            const option = el("option", category.name);
            option.value = category.id;
            select.append(option);
          }
          select.value = channel.category_id || "";
          select.setAttribute("aria-label", "Channel category");
          select.addEventListener("change", () => {
            channel.category_id = select.value || null;
          });
          row.append(
            input,
            select,
            button("Remove", () => {
              document.channels = document.channels.filter((item) => item.id !== channel.id);
              draw();
            }),
          );
          channels.append(row);
        }
        const addChannel = button("Add channel", () => {
          document.channels.push({
            id: crypto.randomUUID(),
            name: "New channel",
            category_id: null,
          });
          draw();
        });
        addChannel.disabled = document.channels.length >= 20;
        channels.append(addChannel);
      }
      draw();
    },
    () => {
      document.name = name.value;
      return api(
        `/organizations/${selected}/workspaces${workspace ? `/${workspace.id}` : ""}`,
        workspace ? "PUT" : "POST",
        { revision: workspace?.revision || null, document },
      );
    },
  );
}
async function editAccess(workspace) {
  const [members, grants] = await Promise.all([
    api(`/organizations/${selected}/members`),
    api(`/organizations/${selected}/workspaces/${workspace.id}/access`),
  ]);
  let member, level;
  openDialog(
    `Access · ${workspace.document.name}`,
    (parent) => {
      parent.append(
        el(
          "p",
          "Organization administrators already have full access. A member can read; a manager can also receive permission to edit this workspace.",
        ),
      );
      member = selectField(
        parent,
        "User",
        members
          .filter((item) => item.role !== "organization_admin")
          .map((item) => [item.user_id, `${item.username} · ${roleNames[item.role]}`]),
      );
      level = selectField(parent, "Access", [
        ["none", "No access"],
        ["read", "Read"],
        ["manage", "Manage (manager role only)"],
      ]);
      const update = () => {
        const grant = grants.find((grant) => grant.user_id === member.value);
        level.value = grant ? (grant.can_manage ? "manage" : "read") : "none";
      };
      member.addEventListener("change", update);
      update();
      if (!member.options.length) {
        parent.append(el("p", "Add a manager or member to this organization first."));
        $("save-dialog").disabled = true;
      }
    },
    () =>
      member.value
        ? api(
            `/organizations/${selected}/workspaces/${workspace.id}/access/${member.value}`,
            level.value === "none" ? "DELETE" : "PUT",
            level.value === "none" ? undefined : { can_manage: level.value === "manage" },
          )
        : Promise.reject(Error("Select a member.")),
  );
}
async function render() {
  if (!token || !me) return;
  const generation = ++rendering;
  notice("");
  $("content").replaceChildren(el("p", "Loading…"));
  $("page-title").textContent = {
    overview: "Overview",
    organizations: "Organizations",
    users: "Users",
    workspaces: "Workspaces",
    members: "Members & roles",
    access: "Workspace access",
    sessions: "My sessions",
  }[view];
  for (const node of document.querySelectorAll("[data-view]"))
    node.classList.toggle("active", node.dataset.view === view);
  try {
    snapshot = selected ? await api(`/sync?organization_id=${encodeURIComponent(selected)}`) : null;
    if (generation !== rendering) return;
    $("content").replaceChildren();
    if (view === "overview") {
      toolbar("One server. Independent organizations. Explicit workspace access.");
      const cards = el("div", undefined, "cards");
      for (const [value, label] of [
        [organizations.length, "Accessible organizations"],
        [snapshot?.workspaces.length || 0, "Visible workspaces"],
        [
          snapshot?.workspaces.reduce((sum, w) => sum + w.document.channels.length, 0) || 0,
          "Channel slots",
        ],
      ]) {
        const card = el("div", undefined, "card");
        card.append(el("strong", String(value)), el("small", label));
        cards.append(card);
      }
      $("content").append(cards);
      const note = el("div", undefined, "empty");
      note.style.marginTop = "22px";
      note.append(
        el("h2", "Connect the desktop app"),
        el(
          "p",
          "In Elo Talks settings, enter this server's HTTPS domain and sign in. Choose an organization to synchronize the workspaces you are allowed to see. Each computer links its own WhatsApp sessions.",
        ),
      );
      $("content").append(note);
    } else if (view === "organizations") {
      toolbar(
        "Organizations isolate memberships, roles and workspace access.",
        me.role === "server_admin" ? button("Create organization", () => editOrganization()) : null,
      );
      table(
        ["Organization", "Your role", "Actions"],
        organizations.map((org) => [
          org.name,
          el("span", roleNames[org.role] || org.role, "badge"),
          actions(
            (org.role === "organization_admin" || me.role === "server_admin") &&
              button("Rename", () => editOrganization(org)),
            me.role === "server_admin" &&
              button(
                "Delete",
                () =>
                  confirmAction(
                    "Delete organization",
                    `Delete ${org.name} and all its workspace metadata and memberships?`,
                    () => api(`/organizations/${org.id}`, "DELETE"),
                  ),
                "danger",
              ),
          ),
        ]),
      );
    } else if (view === "users") {
      if (!orgAdmin()) throw Error("Organization administrator access is required.");
      const users =
        me.role === "server_admin"
          ? await api("/users")
          : (await api(`/organizations/${selected}/members`)).map((member) => ({
              ...member,
              id: member.user_id,
              server_admin: false,
            }));
      if (generation !== rendering) return;
      toolbar(
        "Manage user accounts. Server-wide security changes are reserved for server administrators.",
        button("Create user", createUser),
      );
      table(
        ["Username", "Status", "Server role", "Actions"],
        users.map((user) => [
          user.username,
          user.disabled ? "Disabled" : "Active",
          user.server_admin ? "Server administrator" : "User",
          actions(me.role === "server_admin" && button("Manage", () => editUser(user))),
        ]),
      );
    } else if (view === "members") {
      if (!selected || !orgAdmin()) throw Error("Select an organization you administer.");
      const members = await api(`/organizations/${selected}/members`);
      if (generation !== rendering) return;
      toolbar(
        "Membership defines the role. Workspace grants define what managers and members can access.",
        button("Add existing user", () => editMember()),
      );
      table(
        ["User", "Role", "Actions"],
        members.map((member) => [
          member.username,
          el("span", roleNames[member.role], "badge"),
          actions(
            button("Change role", () => editMember(member)),
            button(
              "Remove",
              () =>
                confirmAction(
                  "Remove membership",
                  `Remove ${member.username} from this organization and revoke their workspace grants?`,
                  () => api(`/organizations/${selected}/members/${member.user_id}`, "DELETE"),
                ),
              "danger",
            ),
          ),
        ]),
      );
    } else if (view === "workspaces" || view === "access") {
      if (!selected) {
        toolbar("Create or select an organization first.");
        return;
      }
      if (view === "access" && !orgAdmin())
        throw Error("Organization administrator access is required.");
      toolbar(
        view === "access"
          ? "Workspace access is denied until explicitly granted."
          : "Manage the categories and channel slots synchronized to desktop clients.",
        view === "workspaces" && orgAdmin()
          ? button("Create workspace", () => editWorkspace())
          : null,
      );
      table(
        ["Workspace", "Categories", "Channels", "Actions"],
        snapshot.workspaces.map((workspace) => [
          workspace.document.name,
          workspace.document.categories.length,
          workspace.document.channels.length,
          actions(
            view === "access"
              ? button("Manage access", () => editAccess(workspace))
              : workspace.can_manage && button("Edit structure", () => editWorkspace(workspace)),
            view === "workspaces" &&
              orgAdmin() &&
              button(
                "Delete",
                () =>
                  confirmAction(
                    "Delete workspace",
                    `Delete ${workspace.document.name}? Connected clients will remove its managed channels.`,
                    () => api(`/organizations/${selected}/workspaces/${workspace.id}`, "DELETE"),
                  ),
                "danger",
              ),
          ),
        ]),
      );
    } else if (view === "sessions") {
      const sessions = await api("/auth/sessions");
      if (generation !== rendering) return;
      toolbar(
        "Only your sessions are listed. Revocation takes effect on the next authenticated request.",
        button("Change my password", () => {
          let current, next;
          openDialog(
            "Change login password",
            (parent) => {
              current = field(parent, "Current password", "", "password");
              next = field(parent, "New password", "", "password");
              next.minLength = 12;
            },
            async () => {
              await api("/auth/password", "POST", {
                current_password: current.value,
                new_password: next.value,
              });
              signOut();
            },
          );
        }),
      );
      table(
        ["Session", "Expires", "Actions"],
        sessions.map((session) => [
          session.current ? "This browser" : session.id,
          new Date(session.expires_at * 1000).toLocaleString(),
          button(
            "Revoke",
            async () => {
              await api(`/auth/sessions/${session.id}`, "DELETE");
              if (session.current) signOut();
              else await render();
            },
            "danger",
          ),
        ]),
      );
    }
  } catch (error) {
    if (generation === rendering) {
      $("content").replaceChildren();
      notice(error.message, true);
    }
  }
}
