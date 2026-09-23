const form = document.querySelector('#scan-form');
const input = document.querySelector('#url');
const button = document.querySelector('#scan-button');
const statusBox = document.querySelector('#status');
const results = document.querySelector('#results');

const esc = (value) => String(value ?? '').replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

function setStatus(message, kind = '') {
  statusBox.hidden = false;
  statusBox.className = `status ${kind}`;
  statusBox.textContent = message;
}

function renderReport(report) {
  results.hidden = false;
  document.querySelector('#target-label').textContent = report.target;
  const counts = report.summary.counts;
  document.querySelector('#metric-grid').innerHTML = [
    ['Total de achados', report.summary.total, ''],
    ['Alta / crítica', (counts.ALTA || 0) + (counts.CRÍTICA || 0), 'high'],
    ['Média', counts.MÉDIA || 0, 'medium'],
    ['Requisições', report.requests, 'low'],
  ].map(([label, value, tone]) => `<div class="metric"><div class="label">${esc(label)}</div><div class="value ${tone}">${esc(value)}</div></div>`).join('');
  document.querySelector('#finding-filter-label').textContent = `${report.summary.total} resultado(s)`;
  document.querySelector('#findings').innerHTML = report.findings.length ? report.findings.map((item) => `
    <article class="finding">
      <div class="finding-top"><h3>${esc(item.title)}</h3><span class="badge ${esc(item.severity)}">${esc(item.severity)}</span></div>
      <div class="finding-meta">${esc(item.category)} · confiança ${esc(item.confidence)}</div>
      <p><strong>Evidência:</strong> ${esc(item.evidence)}</p>
      <p><strong>Recomendação:</strong> ${esc(item.recommendation)}</p>
    </article>`).join('') : '<div class="finding"><p>Nenhum achado foi identificado nas verificações executadas.</p></div>';
  document.querySelector('#observations').innerHTML = (report.observations || []).map((item) => `<li>${esc(item)}</li>`).join('');
  const errors = document.querySelector('#errors-wrap');
  errors.hidden = !(report.errors || []).length;
  document.querySelector('#errors').innerHTML = (report.errors || []).map((item) => `<li>${esc(item)}</li>`).join('');
  document.querySelector('#scope-note').textContent = report.scope;
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  results.hidden = true;
  setStatus('Validando destino e executando verificações passivas…', 'loading');
  try {
    const response = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ url: input.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Não foi possível executar o scan');
    setStatus('Scan concluído.', '');
    renderReport(data);
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#new-scan').addEventListener('click', () => {
  results.hidden = true;
  statusBox.hidden = true;
  input.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
