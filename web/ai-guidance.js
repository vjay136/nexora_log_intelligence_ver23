(() => {
  'use strict';

  const providerMessages = {
    not_requested: 'Controller catalog',
    selected: 'Provider selected a verified catalog action',
    unavailable: 'Provider unavailable. Showing controller guidance.',
    busy: 'Provider capacity is busy. Showing controller guidance.',
    timeout: 'Provider timed out. Showing controller guidance.',
    invalid: 'Provider returned an invalid action. Showing controller guidance.',
  };

  async function render({page, api, esc, pretty, notify, can, isCurrent, previousScope}) {
    const snapshot = await api('/ai/guidance');
    if (!isCurrent()) return;

    const workspaces = snapshot.workspaces || [];
    const current = snapshot.current || {};
    let evaluations = snapshot.evaluations || [];
    const option = (id, label) => `<option value="${esc(id)}">${esc(label)}</option>`;
    const history = (entries, describe, empty) => {
      if (!entries?.length) return `<p>${esc(empty)}</p>`;
      return `<div class="table-wrap"><table><thead><tr><th>Recorded</th><th>Workspace</th><th>Catalog revision</th><th>Details</th></tr></thead><tbody>${entries.map(entry => {
        const payload = entry.payload || {};
        const workspace = workspaces.find(item => item.id === payload.scope?.workspace);
        const tab = workspace?.tabs?.find(item => item.id === payload.scope?.tab);
        const recorded = entry.created_at ? new Date(entry.created_at).toLocaleString() : 'Unavailable';
        return `<tr><td>${esc(recorded)}</td><td>${esc(workspace?.label || payload.scope?.workspace || 'Unavailable')}${tab ? ` · ${esc(tab.label)}` : ''}</td><td><code title="${esc(payload.catalog?.sha256 || '')}">${esc(payload.catalog?.release || '—')} · r${esc(payload.catalog?.version || '—')} · ${esc((payload.catalog?.sha256 || '').slice(0, 12))}</code></td><td>${describe(payload)}</td></tr>`;
      }).join('')}</tbody></table></div>`;
    };
    const showEvaluations = () => history(evaluations,
      payload => `<strong>${esc(payload.selected?.label || 'Unavailable')}</strong><br><small>${esc(providerMessages[payload.provider_status] || 'Unavailable')}</small>`,
      'No guidance evaluations have been recorded.');
    const revisions = snapshot.can_record_revision && can('users:manage') ? `
      <form id="ai-guidance-revision" class="form-grid">
        <label class="field wide">Revision note<input name="note" aria-label="Revision note" aria-describedby="guidance-note-hint" minlength="3" maxlength="512" required>
          <span class="hint" id="guidance-note-hint">Record a note for the workspace, tab and action selected above. Keep notes free of raw logs and credentials.</span>
        </label>
        <button type="submit" class="secondary">Record revision</button>
      </form>` : '';

    page.innerHTML = `
      <section class="panel">
        <div class="section-head"><div><h3>Evaluate workspace guidance</h3>
          <p>${esc(current.release || 'Release unavailable')} · Catalog revision ${esc(current.version ?? 'Unavailable')} · <code class="mono" title="${esc(current.sha256 || '')}">${esc((current.sha256 || '').slice(0, 12))}</code></p>
        </div></div>
        <form id="ai-guidance-evaluation" class="form-grid">
          <label class="field">Workspace<select name="workspace" aria-label="Workspace" required>${workspaces.map(item => option(item.id, item.label)).join('')}</select></label>
          <label class="field">Tab<select name="tab" aria-label="Tab"></select></label>
          <label class="field">Action<select name="action" aria-label="Action"></select></label>
          <label class="field wide">Question (optional)<textarea name="question" aria-label="Question (optional)" aria-describedby="guidance-question-hint" maxlength="2048" rows="3" placeholder="How do I verify that a client applied the current bundle?"></textarea>
            <span class="hint" id="guidance-question-hint">Use a workflow question and leave out log samples and credentials.</span>
          </label>
          <label class="field wide"><span><input name="use_provider" type="checkbox"> Allow the configured provider to select an action</span>
            <span class="hint">A masked question and the available action choices are sent only when selected.</span>
          </label>
          <button class="primary" type="submit">Evaluate guidance</button>
        </form>
        <div class="ai-guidance-result" data-guidance-result aria-live="polite"></div>
      </section>
      ${snapshot.history_status === 'unavailable' ? '<div class="callout warn">Guidance history could not be read.</div>' : ''}
      <section class="panel">
        <h3>Guidance revisions</h3>
        ${revisions}
        ${history(snapshot.revisions, payload => esc(payload.note || 'Unavailable'), 'No guidance revisions have been recorded.')}
      </section>
      <section class="panel">
        <h3>Recent evaluations</h3>
        <div data-guidance-evaluations>${showEvaluations()}</div>
      </section>`;
    page.dataset.page = 'ai-guidance';
    page.dataset.dirty = 'false';

    const form = page.querySelector('#ai-guidance-evaluation');
    const result = page.querySelector('[data-guidance-result]');
    const workspace = form.elements.workspace;
    const tab = form.elements.tab;
    const action = form.elements.action;
    const initialWorkspace = previousScope?.workspace || 'parser-sync';
    if (workspaces.some(item => item.id === initialWorkspace)) workspace.value = initialWorkspace;
    const selectedWorkspace = () => workspaces.find(item => item.id === workspace.value);
    const showActions = () => {
      const selected = selectedWorkspace();
      const tabData = selected?.tabs?.find(item => item.id === tab.value);
      const choices = tabData
        ? [...(selected.actions || []).filter(item => item.id === 'navigate'), ...(tabData.actions || [])]
        : selected?.actions || [];
      action.innerHTML = option('', 'Suggest an action') + choices.map(item => option(item.id, item.label)).join('');
    };
    const showTabs = () => {
      const tabs = selectedWorkspace()?.tabs || [];
      tab.innerHTML = option('', 'All workspace controls') + tabs.map(item => option(item.id, item.label)).join('');
      tab.disabled = tabs.length === 0;
      showActions();
    };
    workspace.addEventListener('change', showTabs);
    tab.addEventListener('change', showActions);
    showTabs();
    if (previousScope?.tab && [...tab.options].some(item => item.value === previousScope.tab)) {
      tab.value = previousScope.tab;
      showActions();
    }
    if (previousScope?.action && [...action.options].some(item => item.value === previousScope.action)) action.value = previousScope.action;

    const scope = () => ({workspace: workspace.value, tab: tab.value, action: action.value});
    const showEvaluation = evaluation => {
      const selected = evaluation.selected || {};
      const evaluatedWorkspace = workspaces.find(item => item.id === evaluation.scope?.workspace);
      const chosenTab = evaluatedWorkspace?.tabs?.find(item => item.id === evaluation.scope?.tab);
      const status = providerMessages[evaluation.provider_status] || 'Provider status unavailable';
      const warning = !['selected', 'not_requested'].includes(evaluation.provider_status);
      result.innerHTML = `<div class="callout ${warning ? 'warn' : ''}">
        <p><strong>${esc(selected.label || 'Guidance unavailable')}</strong>${chosenTab ? ` · ${esc(chosenTab.label)}` : ''}</p>
        <p>${esc(selected.guidance || '')}</p>
        <p>${esc(status)}</p>
        ${evaluation.persisted ? '' : '<p>Evaluation history could not be saved.</p>'}
        <button class="secondary small" type="button" data-action="navigate" data-page="${esc(evaluation.scope?.workspace || '')}">Open workspace</button>
        <details><summary>Catalog evidence</summary><pre>${esc(pretty({catalog: evaluation.catalog, scope: evaluation.scope, action: selected.id, provider: evaluation.provider_id, attempts: evaluation.provider_attempts}))}</pre></details>
      </div>`;
      if (evaluation.evaluation_id) {
        evaluations = [{created_at: evaluation.recorded_at, payload: evaluation}, ...evaluations].slice(0, 20);
        page.querySelector('[data-guidance-evaluations]').innerHTML = showEvaluations();
      }
    };
    form.addEventListener('submit', async event => {
      event.preventDefault();
      event.stopPropagation();
      const button = event.submitter || form.querySelector('[type=submit]');
      button.disabled = true;
      result.textContent = 'Evaluating available actions…';
      try {
        const evaluation = await api('/ai/guidance/evaluate', {method: 'POST', body: {
          ...scope(), question: form.elements.question.value, use_provider: form.elements.use_provider.checked,
        }});
        if (isCurrent() && result.isConnected) {
          showEvaluation(evaluation);
          page.dataset.dirty = 'false';
        }
      } catch (error) {
        if (isCurrent() && result.isConnected) result.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
    const revisionForm = page.querySelector('#ai-guidance-revision');
    revisionForm?.addEventListener('submit', async event => {
      event.preventDefault();
      event.stopPropagation();
      const button = event.submitter || revisionForm.querySelector('[type=submit]');
      button.disabled = true;
      const revisionScope = scope();
      try {
        await api('/ai/guidance/revisions', {method: 'POST', body: {
          ...revisionScope, note: revisionForm.elements.note.value, catalog_hash: current.sha256,
        }});
        if (isCurrent() && revisionForm.isConnected) {
          page.dataset.dirty = 'false';
          notify('Guidance revision recorded');
          await render({page, api, esc, pretty, notify, can, isCurrent, previousScope: revisionScope});
        }
      } catch (error) {
        if (isCurrent() && revisionForm.isConnected) notify(error.message, 'error');
      } finally {
        button.disabled = false;
      }
    });
  }

  window.NLIAIGuidance = {render};
})();
