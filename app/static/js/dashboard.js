/* ============================================================
   WebSecLab v3.0 — 首页「安全实验态势中心」交互 (dashboard.js)
   - ECharts 渲染风险趋势 / 漏洞分布
   - 系统状态每 30 秒 AJAX 轮询刷新 (不整页刷新)
   - 全部统计数据优先来自服务端注入的 window.HOME_DATA
   ============================================================ */
(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }

  /* ---------- 模块⑥ 风险趋势 (扫描次数 / 漏洞数量 / 风险指数) ---------- */
  function renderTrend(data) {
    if (!data || !el('trendChart') || typeof echarts === 'undefined') return;
    var chart = echarts.init(el('trendChart'));
    var dates = (data.dates || []).map(function (d) { return d.slice(5); }); // MM-DD
    var option = {
      tooltip: { trigger: 'axis' },
      legend: { data: ['扫描次数', '漏洞数量', '风险指数'], bottom: 0, textStyle: { fontSize: 11 } },
      grid: { left: 40, right: 16, top: 16, bottom: 40 },
      xAxis: { type: 'category', data: dates, boundaryGap: false,
               axisLine: { lineStyle: { color: '#cbd5e1' } }, axisLabel: { color: '#6b7280' } },
      yAxis: [
        { type: 'value', name: '次数', minInterval: 1,
          axisLabel: { color: '#6b7280' }, splitLine: { lineStyle: { color: '#eef1f6' } } },
        { type: 'value', name: '风险', min: 0, max: 100, position: 'right',
          axisLabel: { color: '#6b7280' }, splitLine: { show: false } }
      ],
      series: [
        { name: '扫描次数', type: 'line', smooth: true, data: data.scan_counts,
          itemStyle: { color: '#06b6d4' }, areaStyle: { color: 'rgba(6,182,212,.12)' } },
        { name: '漏洞数量', type: 'line', smooth: true, data: data.vuln_counts,
          itemStyle: { color: '#a855f7' }, areaStyle: { color: 'rgba(168,85,247,.12)' } },
        { name: '风险指数', type: 'line', smooth: true, yAxisIndex: 1, data: data.risk_scores,
          connectNulls: false, itemStyle: { color: '#3b82f6' }, lineStyle: { width: 2 } }
      ]
    };
    chart.setOption(option);
    window.addEventListener('resize', function () { chart.resize(); });
  }

  /* ---------- 模块⑦ 漏洞风险分布 (环形图) ---------- */
  function renderRisk(data) {
    if (!data || !el('riskChart') || typeof echarts === 'undefined') return;
    var chart = echarts.init(el('riskChart'));
    var colorMap = { Critical: '#dc2626', High: '#f97316', Medium: '#eab308', Low: '#22c55e', Info: '#94a3b8' };
    var dist = (window.HOME_DATA && window.HOME_DATA.risk_distribution) || data || [];
    var pieData = dist.map(function (d) {
      return { name: d.name, value: d.count, itemStyle: { color: colorMap[d.name] || '#94a3b8' } };
    });
    var option = {
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { bottom: 0, textStyle: { fontSize: 11 } },
      series: [{
        type: 'pie', radius: ['45%', '72%'], center: ['50%', '44%'],
        avoidLabelOverlap: true, label: { show: true, formatter: '{c}' },
        data: pieData
      }]
    };
    chart.setOption(option);
    window.addEventListener('resize', function () { chart.resize(); });
  }

  /* ---------- 模块① 系统状态 30s 轮询 ---------- */
  function refreshStatus() {
    fetch('/api/system-status').then(function (r) { return r.json(); }).then(function (list) {
      if (!Array.isArray(list)) return;
      list.forEach(function (s) {
        var card = document.querySelector('.status-card[data-key="' + s.key + '"]');
        if (!card) return;
        card.className = 'status-card status-' + s.status;
        var dot = card.querySelector('.status-dot');
        if (dot) dot.className = 'status-dot';
        var detail = card.querySelector('.status-detail');
        if (detail) detail.textContent = s.detail;
      });
      var hint = el('statusRefreshHint');
      if (hint) hint.innerHTML = '<i class="bi bi-check2-circle"></i> 已更新 ' +
        new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }).catch(function () { /* 静默失败, 保留占位状态 */ });
  }

  /* ---------- 启动 ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    var home = window.HOME_DATA;
    if (home) {
      renderTrend(home.trends);
      renderRisk(home.risk_distribution);
    }
    // 系统状态首屏占位 -> 立即拉一次, 之后每 30 秒
    refreshStatus();
    setInterval(refreshStatus, 30000);
  });
})();
