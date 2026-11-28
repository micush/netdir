"use strict";
// MCP Network Director web GUI: the scheduler page.

VIEWS.scheduler = (() => {
  let status, box, last = "", clip = null;
  try { clip = JSON.parse(localStorage.getItem("netdir_sched_clip") || "null"); } catch (_) { clip = null; }
  const WD = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const NTH = [[1, "1st"], [2, "2nd"], [3, "3rd"], [4, "4th"], [-1, "last"]];
  const MON = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  let localTimes = false; // run times are UTC, like the schedules; the Local time box on the history shows them in this browser's zone
  try { localTimes = localStorage.getItem("sched_local_times") === "1"; } catch (_) { /* no storage */ }
  const when = (u) => (!u ? "–" : localTimes ? new Date(u * 1000).toLocaleString([], { timeZoneName: "short" }) : new Date(u * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC");

  async function call(path, body, done) {
    try { await api("POST", "/api/schedule/" + path, body); if (done) done(); clear(status); await VIEWS.scheduler.poll(true); } catch (e) { fail(status)(e); }
  }
  const nodeName = (id) => { const n = state.nodes.find((x) => x.node_id === id); return n ? (nodeLabel(n)) : id.slice(0, 8); };
  const actionLabel = (t, actions) => (t.action === "shell" ? "Shell command" : (actions || {})[t.action] || t.action);

  function copyTask(t) {
    clip = JSON.parse(JSON.stringify(t));
    try { localStorage.setItem("netdir_sched_clip", JSON.stringify(clip)); } catch (_) { /* no storage */ }
    VIEWS.scheduler.poll(true).catch(() => {});   // the Paste entries appear
    say(status, "info", "Copied “" + t.name + "”. Right-click ▸ Paste adds a copy.");
    setTimeout(() => clear(status), 2500);
  }
  function pasteTask(existing) {
    if (!clip) return;
    const names = new Set(existing.map((t) => t.name.toLowerCase()));
    let name = clip.name + " copy", i = 2;
    while (names.has(name.toLowerCase())) name = clip.name + " copy " + i++;
    const t = Object.assign({}, clip, { name }); delete t.id;
    call("task", { task: t });
  }

  function editor(task, existing) {
    const t = Object.assign({ freq: "daily", at: "12:00:00", action: "backup", window_sec: 0, timeout_sec: 300, days: [1], day: 1, nths: [], weekdays: [], month: 1, every: 1 }, task || {});
    if (t.nth && !(t.nths || []).length) { t.nths = [t.nth]; t.weekdays = [t.weekday || 0]; }
    const isNew = !task;
    const err = h("div", { "aria-live": "polite" });
    const d = h("dialog", { class: "cv-dialog sched-dialog", "aria-label": isNew ? "New task" : "Edit task" });
    const close = () => { try { d.close(); } catch (_) { /* closed */ } d.remove(); };
    d.addEventListener("close", () => d.remove());
    const name = h("input", { type: "text", maxlength: "80", value: t.name || "", "aria-label": "Name", autocomplete: "off" });
    const acts = Object.entries(editorActions);
    const action = h("select", { "aria-label": "Action" }, acts.map(([k, l]) => h("option", { value: k, selected: k === t.action }, l)), h("option", { value: "shell", selected: t.action === "shell" }, "Run a shell command"));
    const cmd = h("textarea", { rows: "4", spellcheck: "false", maxlength: "4096", "aria-label": "Command", class: "mono" }); cmd.value = t.command || "";
    const tmo = h("input", { type: "number", min: "1", max: "86400", value: String(t.timeout_sec || 300), "aria-label": "Time limit in seconds" });
    const ign = h("input", { type: "checkbox", checked: !!t.ignore_exit });
    const shellBox = h("div", {}, h("label", { class: "f wide" }, "Command", cmd),
      h("label", { class: "f" }, "Stop it after (seconds)", tmo),
      h("label", { class: "f check" }, ign, "Ignore the exit status"));
    const allNodes = h("input", { type: "radio", name: "sched-where", checked: !(t.nodes || []).length });
    const someNodes = h("input", { type: "radio", name: "sched-where", checked: (t.nodes || []).length > 0 });
    const nodeBoxes = state.nodes.map((n) => ({ n, el: h("input", { type: "checkbox", checked: (t.nodes || []).includes(n.node_id), disabled: !n.node_id }) }));
    const nodesList = h("div", { class: "sched-nodes" }, nodeBoxes.map(({ n, el }) => h("label", { class: "f check" }, el, nodeLabel(n) + (n.self ? " (this node)" : ""))));
    const allLabel = h("label", { class: "f check" }, allNodes, "Every node of the cluster");
    const where = state.nodes.length > 1
      ? h("div", { class: "f wide" }, h("span", {}, "Runs on"), allLabel, h("label", { class: "f check" }, someNodes, "Only these nodes:"), nodesList)
      : h("div", { class: "hint" }, "Runs on this node.");
    const dateIn = h("input", { type: "date", value: t.date || new Date(Date.now() + 86400000).toISOString().slice(0, 10), "aria-label": "Date (UTC)" });
    const freq = h("select", { "aria-label": "How often" }, [["once", "Once"], ["hourly", "Hourly"], ["daily", "Daily"], ["weekly", "Weekly"], ["monthly", "Monthly"], ["yearly", "Yearly"]].map(([k, l]) => h("option", { value: k, selected: k === t.freq }, l)));
    const every = h("input", { type: "number", min: "1", max: "720", value: String(t.every || 1), "aria-label": "Every how many" });
    const everyUnit = h("span", {});
    const at = h("input", { type: "time", step: "60", value: (t.at || "12:00:00").slice(0, 5), "aria-label": "Time of day" });
    const minute = h("input", { type: "number", min: "0", max: "59", value: String(+(t.at || "00:00:00").split(":")[1] || 0), "aria-label": "Minute past the hour" });
    const days = WD.map((w, i) => ({ i, el: h("input", { type: "checkbox", checked: (t.days || []).includes(i) }) }));
    const dayRow = h("div", { class: "sched-days" }, days.map(({ i, el }) => h("label", { class: "f check" }, el, WD[i].slice(0, 3))));
    const byDay = h("input", { type: "radio", name: "sched-by", checked: !(t.nths || []).length });
    const byNth = h("input", { type: "radio", name: "sched-by", checked: (t.nths || []).length > 0 });
    const dom = h("select", { "aria-label": "Day of the month" }, Array.from({ length: 31 }, (_, i) => h("option", { value: String(i + 1), selected: t.day === i + 1 }, String(i + 1))), h("option", { value: "-1", selected: t.day === -1 }, "last day"));
    const nths = NTH.map(([v, l]) => ({ v, el: h("input", { type: "checkbox", checked: (t.nths || []).includes(v) || (!(t.nths || []).length && v === 3) }) }));
    const nthRow = h("span", { class: "sched-days" }, nths.map(({ v, el }) => h("label", { class: "f check" }, el, NTH.find((x) => x[0] === v)[1])));
    const eachSel = h("select", { "aria-label": "Which of those days" }, h("option", { value: "first", selected: !t.each_day && !t.pick_day }, "first of those days only"), h("option", { value: "each", selected: !!t.each_day }, "each of those days"), h("option", { value: "pick", selected: !!t.pick_day }, "one of those days, chosen per node"));
    const wds = WD.map((w, i) => ({ i, el: h("input", { type: "checkbox", checked: (t.weekdays || []).includes(i) || (!(t.weekdays || []).length && i === 6) }) }));
    const wdRow = h("span", { class: "sched-days" }, wds.map(({ i, el }) => h("label", { class: "f check" }, el, WD[i].slice(0, 3))));
    const month = h("select", { "aria-label": "Month" }, MON.map((m, i) => h("option", { value: String(i + 1), selected: t.month === i + 1 }, m)));
    const monthRow = h("label", { class: "f" }, "Month", month);
    const months = MON.map((m, i) => ({ i, el: h("input", { type: "checkbox", checked: (t.months || []).includes(i + 1) }) }));
    const monthsRow = h("div", { class: "f wide", title: "Tick the months it runs in; none ticked means every month" }, h("span", {}, "Only in"),
      h("div", { class: "sched-days sched-months" }, months.map(({ i, el }) => h("label", { class: "f check" }, el, MON[i].slice(0, 3)))));
    const dayBox = h("div", { class: "f wide" }, h("span", {}, "On"),
      h("label", { class: "f check" }, byDay, "day", dom, " of the month"),
      h("div", { class: "f check sched-nthrow" }, byNth, "the", nthRow, wdRow, "of the month, run on", eachSel));
    // The offset window of an older version is shown as its To time when it fits (whole minutes, under a day, under an hour for an hourly task); otherwise it is kept as it was.
    let legacyWin = t.until ? 0 : t.window_sec || 0, toTime = t.until || ""; // with a To time the saved window_sec is only that To time worked out: clearing To must clear it
    if (!toTime && legacyWin > 0 && legacyWin % 60 === 0 && legacyWin < (t.freq === "hourly" ? 3600 : 86400)) {
      const [ah, am] = (t.at || "00:00:00").split(":").map(Number), e = ah * 60 + am + legacyWin / 60;
      toTime = String(Math.floor(e / 60) % 24).padStart(2, "0") + ":" + String(e % 60).padStart(2, "0"); legacyWin = 0;
    }
    const until = h("input", { type: "time", value: t.freq === "hourly" ? "" : toTime, "aria-label": "To (UTC)" });
    const untilMin = h("input", { type: "number", min: "0", max: "59", value: t.freq === "hourly" && toTime ? String(+toTime.split(":")[1]) : "", "aria-label": "To minute past the hour" });
    const enabled = h("input", { type: "checkbox", checked: !t.disabled });
    const rows = {
      shell: shellBox, date: h("label", { class: "f" }, "On (UTC)", dateIn), every: h("label", { class: "f" }, "Every", h("span", { class: "sched-every" }, every, everyUnit)),
      at: h("div", { class: "f sched-range" }, h("label", { class: "f" }, "At (UTC)", at), h("label", { class: "f" }, "To (optional)", until)), minute: h("div", { class: "f sched-range" }, h("label", { class: "f" }, "At minute", minute), h("label", { class: "f" }, "To minute (optional)", untilMin)), days: h("div", { class: "f wide" }, h("span", {}, "On"), dayRow), month: monthRow, day: dayBox, months: monthsRow,
    };
    const sync = () => {
      const f = freq.value;
      rows.shell.hidden = action.value !== "shell";
      const unitName = { hourly: "hour", daily: "day", weekly: "week", monthly: "month", yearly: "year" }[f];
      everyUnit.textContent = " " + unitName + (+every.value === 1 ? "" : "s");
      every.max = { hourly: 720, daily: 366, weekly: 52, monthly: 24, yearly: 10 }[f];
      rows.date.hidden = f !== "once"; rows.every.hidden = f === "once";
      rows.at.hidden = f === "hourly"; rows.minute.hidden = f !== "hourly";
      rows.months.hidden = !["daily", "weekly", "monthly"].includes(f); rows.days.hidden = f !== "weekly"; rows.month.hidden = f !== "yearly"; rows.day.hidden = f !== "monthly" && f !== "yearly";
      dom.disabled = !byDay.checked; nths.concat(wds).forEach((x) => { x.el.disabled = !byNth.checked; }); eachSel.disabled = !byNth.checked;
      // with auto-update on, the online update is for one node: the release staged on it reaches the others
      const oneNode = action.value === "update_online" && editorAuto && state.nodes.length > 1;
      allLabel.hidden = oneNode;
      if (oneNode) {
        someNodes.checked = true;
        const on = nodeBoxes.filter((x) => x.el.checked);
        if (!on.length) { const me = nodeBoxes.find((x) => x.n.self) || nodeBoxes[0]; if (me) me.el.checked = true; }
        else on.slice(1).forEach((x) => { x.el.checked = false; });
      }
      nodesList.hidden = !someNodes.checked;
    };
    [action, freq, every, byDay, byNth, allNodes, someNodes, until].forEach((el) => el.addEventListener("change", sync));
    nodeBoxes.forEach(({ el }) => el.addEventListener("change", () => { if (action.value === "update_online" && editorAuto && state.nodes.length > 1 && el.checked) nodeBoxes.forEach((x) => { if (x.el !== el) x.el.checked = false; }); }));
    every.addEventListener("input", sync); until.addEventListener("input", sync);
    const submit = (ev) => {
      ev.preventDefault();
      const f = freq.value;
      const task = { id: isNew ? "" : t.id, name: name.value.trim(), action: action.value, freq: f, every: f === "once" ? 1 : Math.max(1, +every.value || 1),
        window_sec: (f === "hourly" ? untilMin.value !== "" : until.value !== "") ? 0 : (f === "hourly" && legacyWin >= 3600 ? 0 : legacyWin), disabled: !enabled.checked };
      if (action.value === "shell") { task.command = cmd.value; task.timeout_sec = +tmo.value || 300; task.ignore_exit = ign.checked; }
      if (f === "hourly") { const m = Math.min(59, Math.max(0, +minute.value || 0)); task.at = "00:" + String(m).padStart(2, "0") + ":00"; } else task.at = at.value.length === 5 ? at.value + ":00" : at.value;
      if (f === "once") { if (!dateIn.value) { errorBox(err, "Pick the date."); return; } task.date = dateIn.value; }
      if (f === "weekly") task.days = days.filter((x) => x.el.checked).map((x) => x.i);
      if (f === "monthly" || f === "yearly") { if (byNth.checked) { task.nths = nths.filter((x) => x.el.checked).map((x) => x.v); task.weekdays = wds.filter((x) => x.el.checked).map((x) => x.i); if (!task.nths.length || !task.weekdays.length) { errorBox(err, "Pick at least one occurrence and one weekday."); return; } task.each_day = eachSel.value === "each"; task.pick_day = eachSel.value === "pick"; } else task.day = +dom.value; }
      if (f === "yearly") task.month = +month.value;
      if (["daily", "weekly", "monthly"].includes(f)) { const ms = months.filter((x) => x.el.checked).map((x) => x.i + 1); if (ms.length && ms.length < 12) task.months = ms; }
      if (f === "hourly" && untilMin.value !== "") {
        const um = Math.min(59, Math.max(0, +untilMin.value || 0));
        if (um === Math.min(59, Math.max(0, +minute.value || 0))) { errorBox(err, "The To minute must differ from the At minute."); return; }
        task.until = "00:" + String(um).padStart(2, "0");
      } else if (f !== "hourly" && until.value) task.until = until.value.slice(0, 5);
      if (state.nodes.length > 1 && someNodes.checked) task.nodes = nodeBoxes.filter((x) => x.el.checked).map((x) => x.n.node_id);
      if (state.nodes.length > 1 && someNodes.checked && !task.nodes.length) { errorBox(err, "Pick at least one node, or choose every node."); return; }
      if (!task.name) { errorBox(err, "Give the task a name."); return; }
      api("POST", "/api/schedule/task", { task }).then(() => { close(); VIEWS.scheduler.poll(true); }).catch((e) => { if (e.message !== "unauthenticated") errorBox(err, e.message); });
    };
    d.append(h("button", { class: "dlg-x", type: "button", "aria-label": "Close", title: "Close", onclick: close }, "✕"), h("h2", {}, isNew ? "New task" : "Edit task"),
      h("form", { onsubmit: submit },
        h("div", { class: "grid" },
          h("label", { class: "f wide" }, "Name", name),
          h("label", { class: "f wide" }, "Does", action), rows.shell, where,
          h("label", { class: "f" }, "How often", freq), rows.date, rows.every, rows.at, rows.minute, rows.days, rows.month, rows.day, rows.months,
          h("label", { class: "f check wide" }, enabled, "Enabled")),
        err,
        h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "submit" }, isNew ? "Add task" : "Save"), h("button", { class: "btn", type: "button", onclick: close }, "Cancel"))));
    root.append(d); sync(); d.showModal(); name.focus();
  }
  let editorActions = {}, editorAuto = false;

  const openRuns = new Set();   // history rows whose output is expanded: kept open when the page redraws
  function draw(st) {
    const sig = JSON.stringify([Object.assign({}, st, { now: 0 }), localTimes, openRuns.size, clip && clip.name, state.nodes.map((n) => [n.node_id, nodeLabel(n)])]);
    if (sig === last) return;
    last = sig;
    editorActions = st.actions || {}; editorAuto = !!st.auto_update;
    const tasks = st.tasks.map((v) => v.task);
    const real = box; box = h("div", {});
    try {
      const menu = (v) => rowMenu([["Edit", () => editor(v.task, tasks)], ["Copy", () => copyTask(v.task)], clip ? ["Paste", () => pasteTask(tasks)] : null, "-",
        ["Run now on", [["this node", () => { if (confirm("Run “" + v.name + "” on this node now?")) call("run", { id: v.id }); }],
          ["all nodes", () => { if (confirm("Run “" + v.name + "” on every node it is for now? The nodes start 1 minute apart, each when it is free.")) call("run", { id: v.id, all: true }); }]]],
        [v.disabled ? "Enable" : "Disable", () => call("task", { task: Object.assign({}, v.task, { disabled: !v.disabled }) })], "-",
        ["Delete", () => { if (confirm("Delete the task “" + v.name + "”?")) call("delete", { id: v.id }); }, "danger"]].filter(Boolean));
      const emptyMenu = rowMenu([["New task", () => editor(null, tasks)], clip ? ["Paste", () => pasteTask(tasks)] : null].filter(Boolean));
      const lastCell = (v) => v.last ? h("span", { title: v.last.output || "" }, pill(v.last.status, v.last.status === "ok" ? "ok" : v.last.status === "failed" ? "bad" : v.last.status === "running" ? "info" : "warn"), " ", when(v.last.start)) : h("span", { class: "muted" }, "never");
      const where = (v) => (v.task.nodes || []).length ? v.task.nodes.map(nodeName).join(", ") : "every node";
      const row = (v) => h("tr", { tabindex: "0", class: v.disabled ? "paused" : "", oncontextmenu: menu(v), ondblclick: () => editor(v.task, tasks) },
        h("td", {}, v.name), h("td", {}, actionLabel(v.task, st.actions), v.task.action === "shell" ? h("div", { class: "mono small muted sched-cmd", title: v.task.command }, v.task.command) : null),
        h("td", {}, where(v)), h("td", {}, v.describe),
        h("td", {}, v.disabled ? pill("disabled", "") : !v.applies ? h("span", { class: "muted" }, "not for this node") : v.running ? pill("running", "info") : v.queued ? pill("waiting for another task", "warn") : v.next_run ? h("span", { title: "scheduled for " + when(v.next) }, when(v.next_run)) : "–"),
        h("td", {}, lastCell(v)));
      box.append(section("Scheduled tasks",
        h("div", { class: "toolbar" }, h("button", { class: "btn primary", type: "button", onclick: () => editor(null, tasks) }, "New task")),
        h("div", { class: "scroll", oncontextmenu: emptyMenu }, h("table", { class: "sched" },
          h("thead", {}, h("tr", {}, ["Task", "Does", "Runs on", "Schedule", ["Next run", "(this node)"], ["Last run", "(this node)"]].map((x) => (Array.isArray(x) ? h("th", {}, x[0], h("br"), x[1]) : h("th", {}, x))))),
          h("tbody", {}, st.tasks.length ? st.tasks.map(row) : h("tr", {}, h("td", { colspan: 6, class: "empty" }, "No tasks yet. Add one with New task, or right-click here.")))))));
      const localBox = h("input", { type: "checkbox", checked: localTimes });
      localBox.addEventListener("change", () => { localTimes = localBox.checked; try { localStorage.setItem("sched_local_times", localTimes ? "1" : "0"); } catch (_) { /* no storage */ } last = ""; draw(st); });
      box.append(h("div", { class: "card" }, h("header", {}, h("h2", {}, tc("History of this node")), h("label", { class: "nt-opt sched-local", title: "Show the times in this browser's time zone instead of UTC" }, localBox, " Local time")), h("div", { class: "body" },
        h("div", { class: "scroll" }, h("table", { class: "sched" },
          h("thead", {}, h("tr", {}, ["Started", "Task", "Result", "Output"].map((x) => h("th", {}, x)))),
          h("tbody", {}, st.history.length ? st.history.slice(0, 60).map((r) => h("tr", {},
            h("td", {}, when(r.start)), h("td", {}, r.name),
            h("td", {}, pill(r.status, r.status === "ok" ? "ok" : r.status === "failed" ? "bad" : r.status === "running" ? "info" : "warn"), r.end && r.end > r.start ? h("span", { class: "small muted" }, " " + (r.end - r.start) + " s") : null),
            h("td", { class: "wrap" }, r.output ? h("details", { open: openRuns.has(r.task + "|" + r.start), ontoggle: (e) => { const k = r.task + "|" + r.start; if (e.target.open) openRuns.add(k); else openRuns.delete(k); } }, h("summary", {}, r.output.split("\n")[0].slice(0, 100)), h("pre", { class: "nt-out" }, r.output)) : ""))) : h("tr", {}, h("td", { colspan: 4, class: "empty" }, "Nothing has run on this node yet."))))))));
    } finally { morph(real, box); box = real; }
  }

  return {
    async mount(main) {
      status = h("div", { "aria-live": "polite" }); box = h("div", {}); last = "";
      main.append(status, box);
      try { draw((await api("GET", "/api/schedule")).data); } catch (e) { fail(status)(e); }
    },
    async poll(force) { if (force) last = ""; draw((await api("GET", "/api/schedule")).data); },
    poll_ms: 5000,
  };
})();
