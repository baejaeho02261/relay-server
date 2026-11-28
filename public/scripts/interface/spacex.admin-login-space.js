'use strict';

(() => {
  const screen = document.getElementById('login-screen');
  const earth = document.getElementById('login-earth');
  const form = document.getElementById('login-form');
  const password = document.getElementById('login-password');
  const error = document.getElementById('login-error');
  const canvas = document.getElementById('login-space');
  if (!screen || !earth || !form || !password || !error || !canvas) return;

  const ctx = canvas.getContext('2d', {alpha: false});
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  const scanDuration = 660, collapseDuration = 580, maxMaskDots = 80;
  const scene = {scanAt: 0, collapseAt: 0, count: 0, phase: 'idle'};
  let earthHovered = false, earthHighlight = 0, clipboardAttempt = 0;
  function clearAnimation() {
    scene.phase = 'idle';
    scene.count = 0;
    password.readOnly = false;
    screen.removeAttribute('aria-busy');
    earth.removeAttribute('aria-disabled');
  }
  function closeEditor(restoreFocus) {
    if (form.hidden) return;
    clipboardAttempt++;
    clearAnimation();
    password.value = '';
    error.textContent = '';
    form.hidden = true;
    earth.setAttribute('aria-expanded', 'false');
    earth.setAttribute('aria-label', '클립보드 비밀번호로 관리자 로그인');
    if (restoreFocus) earth.focus();
  }
  // Credentials can only be sent by the administrator application's API handler.
  form.addEventListener('submit', event => event.preventDefault());
  earth.addEventListener('click', async event => {
    if (scene.phase !== 'idle') return;
    if (!form.hidden) {
      if (password.value) form.requestSubmit();
      else password.focus({preventScroll:true});
      return;
    }
    form.hidden = false;
    earth.setAttribute('aria-expanded', 'true');
    earth.setAttribute('aria-label', '관리자 비밀번호 제출');
    password.focus({preventScroll:true});
    if (!event.isTrusted || !window.isSecureContext || !navigator.clipboard?.readText) return;

    const attempt = ++clipboardAttempt;
    let value;
    try {
      value = (await navigator.clipboard.readText()).trim();
    } catch (_) {
      return;
    }
    // A clipboard prompt can outlive the editor or overlap manual entry.
    if (attempt !== clipboardAttempt || form.hidden || password.value || document.hidden ||
        screen.classList.contains('hidden') || scene.phase !== 'idle') return;
    if (!value || value.length > 4096 || /[\r\n]/.test(value)) return;
    password.value = value;
    form.requestSubmit();
  });
  earth.addEventListener('pointerenter', event => {
    earthHovered = event.pointerType !== 'touch';
    if (ctx) requestFrame();
  });
  earth.addEventListener('pointerleave', () => {
    earthHovered = false;
    if (ctx) requestFrame();
  });
  password.addEventListener('input', () => {
    clipboardAttempt++;
    if (ctx) requestFrame();
  });
  password.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.isComposing || scene.phase !== 'idle') return;
    event.preventDefault();
    if (password.value) form.requestSubmit();
  });
  screen.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || form.hidden || event.isComposing || scene.phase !== 'idle') return;
    event.preventDefault();
    closeEditor(true);
  });
  window.spacexLoginOrbit = Object.freeze({
    begin() {
      clipboardAttempt++;
      scene.count = Math.min(maxMaskDots, password.value.length);
      scene.scanAt = window.performance.now();
      scene.phase = 'scan';
      password.readOnly = true;
      screen.setAttribute('aria-busy', 'true');
      earth.setAttribute('aria-disabled', 'true');
      if (ctx) requestFrame();
    },
    async accept() {
      if (!ctx || reducedMotion?.matches || document.hidden || scene.phase !== 'scan') return;
      const remainingScan = Math.max(0, scanDuration - (window.performance.now() - scene.scanAt));
      if (remainingScan) await new Promise(resolve => window.setTimeout(resolve, remainingScan));
      if (scene.phase !== 'scan' || document.hidden || screen.classList.contains('hidden')) return;
      scene.phase = 'collapse';
      scene.collapseAt = window.performance.now();
      requestFrame();
      await new Promise(resolve => window.setTimeout(resolve, collapseDuration));
    },
    reject() {
      clearAnimation();
      if (!form.hidden) password.focus({preventScroll:true});
      if (ctx) requestFrame();
    }
  });
  new MutationObserver(() => {
    if (screen.classList.contains('hidden')) closeEditor(false);
    if (ctx) requestFrame();
  }).observe(screen, {attributeFilter: ['class']});

  if (!ctx) return;
  const tau = 2 * Math.PI;
  const borderInk = [48, 50, 57];
  const hoverBorderInk = [64, 66, 74];
  const starInk = '#a7b6cd';
  const satellites = [
    {period: 12, offset: -.56, distance: 1.22},
    {period: 16.1, offset: 1.68, distance: 1.32},
    {period: 20.4, offset: 3.63, distance: 1.42}
  ];
  const satelliteHighlights = satellites.map(() => 0);
  let pointer = null, surfaceLeft = 0, surfaceTop = 0;
  let width = 0, height = 0, centerX = 0, centerY = 0, radius = 0, pixelScale = 0;
  let stars = [], atlas, projected, places, landPath, tinyPath, mappedLongitude = NaN;
  let frame = 0, lastTime = 0, elapsed = 0, earthTime = 0;
  let maskCount = 0, maskPoints = [], maskStarted = -1, maskFrom = 0;

  function seed(value) {
    value = Math.imul(value ^ (value >>> 16), 0x7feb352d);
    value = Math.imul(value ^ (value >>> 15), 0x846ca68b);
    return ((value ^ (value >>> 16)) & 65535) / 65535;
  }
  const clamp = value => Math.min(1, Math.max(0, value));
  function ease(value) { return value * value * (3 - 2 * value); }
  const detailStars = Array.from({length: 99}, (_, index) => {
    const id = 131 + index * 7;
    return { x: ((index % 9) + .14 + .72 * seed(id)) / 4.5 - 1,
      y: (Math.floor(index / 9) + .14 + .72 * seed(id + 1)) / 5.5 - 1,
      phase: tau * seed(id + 2), bright: index % 19 === 7 };
  }).filter(({x, y}) => x * x + y * y <= .875);

  function resize() {
    if (screen.classList.contains('hidden')) return;
    const nextWidth = canvas.clientWidth, nextHeight = canvas.clientHeight;
    if (!nextWidth || !nextHeight) return;
    const scale = Math.min(2, window.devicePixelRatio || 1);
    const surface = canvas.getBoundingClientRect();
    surfaceLeft = surface.left;
    surfaceTop = surface.top;
    const planet = earth.getBoundingClientRect();
    const nextX = planet.left - surface.left + planet.width / 2;
    const nextY = planet.top - surface.top + planet.height / 2;
    if (nextWidth === width && nextHeight === height && scale === pixelScale &&
        nextX === centerX && nextY === centerY && planet.width === radius * 2) return;
    width = nextWidth;
    height = nextHeight;
    pixelScale = scale;
    centerX = nextX;
    centerY = nextY;
    radius = planet.width / 2;
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    ctx.setTransform(scale, 0, 0, scale, 0, 0);
    mappedLongitude = NaN;
    const columns = Math.max(12, Math.min(34, Math.round(width / 40)));
    const rows = Math.max(12, Math.min(26, Math.round(height / 32)));
    stars = Array.from({length: columns * rows}, (_, index) => {
      const id = 1103 + index * 9;
      return {x: ((index % columns) + .15 + .70 * seed(id + 2)) * width / columns,
        y: (Math.floor(index / columns) + .15 + .70 * seed(id + 3)) * height / rows,
        dx: .075 * width / columns, dy: .065 * height / rows,
        phase: tau * seed(id), rate: .34 + .65 * seed(id + 1),
        opacity: .14 + .31 * seed(id + 4), radius: .36 + .45 * seed(id + 5),
        bright: index % 29 === 7};
    });
    requestFrame();
  }

  function dot(x, y, size, opacity, color = starInk) {
    ctx.globalAlpha = opacity;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, size, 0, tau);
    ctx.fill();
  }

  function cross(x, y, size, opacity) {
    ctx.globalAlpha = opacity;
    ctx.strokeStyle = starInk;
    ctx.lineWidth = .8;
    ctx.beginPath();
    ctx.moveTo(x - size, y);
    ctx.lineTo(x + size, y);
    ctx.moveTo(x, y - size);
    ctx.lineTo(x, y + size);
    ctx.stroke();
  }

  function drawStars() {
    const scale = Math.max(.85, Math.min(1.55, radius / 103));
    for (const star of stars) {
      const t = elapsed * star.rate;
      const x = star.x + star.dx * Math.cos(t + star.phase);
      const y = star.y + star.dy * Math.sin(t + star.phase);
      const twinkle = .70 + .30 * Math.sin(2.1 * t + star.phase);
      dot(x, y, scale * star.radius, star.opacity * twinkle);
      if (star.bright) cross(x, y, scale * (2 + .60 * twinkle), .37 + .24 * twinkle);
    }
    for (const star of detailStars) {
      const x = centerX + star.x * radius;
      const y = centerY + star.y * radius;
      const twinkle = .75 + .25 * Math.sin(elapsed * tau / 16 + star.phase);
      dot(x, y, Math.max(.32, radius * (star.bright ? .008 : .0048)), twinkle * (star.bright ? .51 : .37));
      if (star.bright) cross(x, y, radius * .018, twinkle * .37);
    }
  }

  // Orthographic globe projection from the native B atlas. Only the public map
  // vertices enter the canvas, along with a bounded count of mask dots.
  function project(source, target, longitude) {
    const sine = Math.sin(longitude), cosine = Math.cos(longitude);
    for (let index = 0; index < source.length; index += 3) {
      const x = source[index] / 32767;
      const y = source[index + 1] / 32767;
      const z = source[index + 2] / 32767;
      const front = z * cosine + x * sine;
      target[index] = x * cosine - z * sine;
      target[index + 1] = front * .3420201 - y * .9396926;
      target[index + 2] = front * .9396926 + y * .3420201;
    }
  }

  function traceCountries(path) {
    for (let index = 0; index < atlas.lines.length; index += 2) {
      const a = atlas.lines[index] * 3, b = atlas.lines[index + 1] * 3;
      let ax = projected[a], ay = projected[a + 1], bx = projected[b], by = projected[b + 1];
      const az = projected[a + 2], bz = projected[b + 2];
      if (az < 0 && bz < 0) continue;
      if (az < 0) {
        const t = az / (az - bz), x = ax + (bx - ax) * t, y = ay + (by - ay) * t;
        const length = Math.hypot(x, y) || 1;
        ax = x / length;
        ay = y / length;
      } else if (bz < 0) {
        const t = bz / (bz - az), x = bx + (ax - bx) * t, y = by + (ay - by) * t;
        const length = Math.hypot(x, y) || 1;
        bx = x / length;
        by = y / length;
      }
      path.moveTo(centerX + ax * radius, centerY + ay * radius);
      path.lineTo(centerX + bx * radius, centerY + by * radius);
    }
  }

  function traceTinyCountries(path) {
    const size = Math.max(.65, Math.min(2, radius * .0085));
    for (let index = 0; index < places.length; index += 3) {
      if (places[index + 2] < .12) continue;
      const x = centerX + places[index] * radius, y = centerY + places[index + 1] * radius;
      path.moveTo(x + size, y);
      path.arc(x, y, size, 0, tau);
    }
  }

  function drawCountries(longitude, color, opacity) {
    if (Number.isNaN(mappedLongitude) || Math.abs(mappedLongitude - longitude) * radius > .72) {
      mappedLongitude = longitude;
      project(atlas.points, projected, longitude);
      project(atlas.places, places, longitude);
      if (window.Path2D) {
        landPath = new Path2D();
        tinyPath = new Path2D();
        traceCountries(landPath);
        traceTinyCountries(tinyPath);
      }
    }
    ctx.globalAlpha = opacity * .92;
    ctx.strokeStyle = color;
    ctx.lineWidth = Math.max(.65, radius * .0083);
    ctx.lineCap = 'round';
    if (landPath) ctx.stroke(landPath);
    else {
      ctx.beginPath();
      traceCountries(ctx);
      ctx.stroke();
    }
    ctx.fillStyle = color;
    if (tinyPath) ctx.fill(tinyPath);
    else {
      ctx.beginPath();
      traceTinyCountries(ctx);
      ctx.fill();
    }
  }

  function satellitePosition({period, offset, distance}) {
    const angle = offset + (elapsed % period) * tau / period;
    return {sine: Math.sin(angle), cosine: Math.cos(angle), distance};
  }

  function outlineColor(highlight) {
    const channels = borderInk.map((value, index) =>
      Math.round(value + (hoverBorderInk[index] - value) * highlight));
    return `rgb(${channels.join(', ')})`;
  }

  function satelliteHovered({sine, cosine, distance}) {
    if (!pointer || !radius || scene.phase !== 'idle') return false;
    const size = radius * .084;
    const dx = (pointer.x - surfaceLeft - centerX - cosine * radius * distance) / size;
    const dy = (pointer.y - surfaceTop - centerY - sine * radius * distance) / size;
    const along = -sine * dx + cosine * dy;
    const across = cosine * dx + sine * dy;
    return Math.abs(along) <= 1.80 && across >= -.94 && across <= .65;
  }

  function drawSatellite({sine, cosine, distance}, color, fade) {
    const size = radius * .084;
    ctx.save();
    ctx.transform(-sine * size, cosine * size, cosine * size, sine * size,
      centerX + cosine * radius * distance, centerY + sine * radius * distance);
    ctx.strokeStyle = color;
    ctx.lineWidth = Math.max(.13, .77 / size);
    ctx.globalAlpha = fade;
    ctx.strokeRect(-.35, -.32, .7, .64);
    ctx.strokeRect(-1.46, -.26, 1, .52);
    ctx.strokeRect(.46, -.26, 1, .52);
    ctx.beginPath();
    ctx.moveTo(-.46, 0); ctx.lineTo(-.35, 0);
    ctx.moveTo(.35, 0); ctx.lineTo(.46, 0);
    ctx.moveTo(0, -.32); ctx.lineTo(0, -.61);
    ctx.moveTo(-.96, -.26); ctx.lineTo(-.96, .26);
    ctx.moveTo(.96, -.26); ctx.lineTo(.96, .26);
    ctx.stroke();
    dot(0, 0, .081, .65 * fade, color);
    dot(0, -.61, .081, (.55 + .45 * Math.max(0, Math.cos(elapsed * tau / 2.6))) * fade, color);
    for (const side of [-1, 1]) {
      dot(side * .69, .03, .071, .59 * fade, color);
      dot(side * 1.22, -.04, .055, .46 * fade, color);
    }
    ctx.restore();
  }

  function buildMaskLayout(longitude) {
    if (!atlas) return Array.from({length: maxMaskDots}, (_, index) => {
      const distance = .86 * Math.sqrt(index / maxMaskDots);
      const angle = index * Math.PI * (3 - Math.sqrt(5));
      return {x: distance * Math.cos(angle), y: distance * Math.sin(angle)};
    });
    const coordinates = new Float32Array(atlas.slots.length);
    project(atlas.slots, coordinates, longitude);
    const candidates = [];
    for (let index = 0; index < coordinates.length; index += 3) {
      if (coordinates[index + 2] < .49) continue;
      const x = coordinates[index], y = coordinates[index + 1];
      candidates.push({x, y, distance: 1 - .70 * (x * x + y * y)});
    }
    const selected = [];
    for (let count = 0; count < maxMaskDots && candidates.length; count++) {
      let best = 0;
      for (let index = 1; index < candidates.length; index++) {
        if (candidates[index].distance > candidates[best].distance) best = index;
      }
      const [point] = candidates.splice(best, 1);
      selected.push(point);
      for (const candidate of candidates) {
        const dx = candidate.x - point.x, dy = candidate.y - point.y;
        candidate.distance = Math.min(candidate.distance, dx * dx + dy * dy);
      }
    }
    return selected;
  }

  function drawMask(count, longitude, collapse) {
    if (!count) {
      if (maskCount) maskPoints = [];
      maskCount = 0;
      return;
    }
    if (!maskPoints.length) maskPoints = buildMaskLayout(longitude);
    if (count !== maskCount) {
      maskStarted = elapsed;
      maskFrom = Math.min(maskCount, count);
      maskCount = count;
    }
    for (let index = 0; index < Math.min(count, maskPoints.length); index++) {
      let {x, y} = maskPoints[index];
      const delay = Math.min(index - maskFrom, 15) * .006;
      const reveal = scene.phase !== 'idle' || reducedMotion?.matches || index < maskFrom
        ? 1 : .72 + .28 * ease(clamp((elapsed - maskStarted - delay) / .13));
      const pull = ease(clamp(collapse * 1.29 - .18 * seed(index + 19)));
      const angle = pull * 4.8;
      const nextX = (x * Math.cos(angle) - y * Math.sin(angle)) * (1 - pull);
      y = (x * Math.sin(angle) + y * Math.cos(angle)) * (1 - pull);
      x = nextX;
      if (pull < 1) {
        const px = centerX + x * radius, py = centerY + y * radius;
        const size = Math.max(2.15, radius * .016) * (.75 + .25 * reveal) * (1 - .68 * pull);
        dot(px, py, size + .8, .94 * (1 - pull), '#000');
        dot(px, py, size, reveal * (1 - pull), '#e4f1ff');
      }
    }
  }

  function drawScan(positions, progress) {
    const count = Math.min(scene.count, maskPoints.length);
    for (const [index, {sine, cosine, distance}] of positions.entries()) {
      const step = clamp(progress * 1.22 - index * .08) * Math.ceil(count / positions.length);
      const first = Math.max(0, Math.floor(step - 2));
      for (let hit = first; hit <= step; hit++) {
        const pointIndex = hit * positions.length + index;
        if (pointIndex >= count) continue;
        const {x, y} = maskPoints[pointIndex];
        const sx = centerX + cosine * radius * distance, sy = centerY + sine * radius * distance;
        const px = centerX + x * radius, py = centerY + y * radius;
        const fade = clamp(1 - Math.abs(step - hit - .30) / 2);
        ctx.strokeStyle = starInk;
        ctx.globalAlpha = .60 * fade;
        ctx.lineWidth = Math.max(.7, radius * .0065);
        ctx.beginPath();
        ctx.moveTo(sx, sy);
        ctx.lineTo(px, py);
        ctx.stroke();
        dot(px, py, Math.max(2, radius * .018), .52 * fade);
      }
    }
  }

  function drawBlackHole(progress) {
    const horizon = radius * (.02 + .16 * ease(clamp(progress * 2)));
    const fade = Math.sin(progress * Math.PI) ** .68;
    ctx.fillStyle = '#000';
    ctx.globalAlpha = fade;
    ctx.beginPath();
    ctx.arc(centerX, centerY, horizon, 0, tau);
    ctx.fill();
    ctx.strokeStyle = starInk;
    for (let index = 0; index < 4; index++) {
      const ring = horizon + radius * index * .086 * (1 - progress);
      ctx.globalAlpha = fade * (.62 - index * .12);
      ctx.lineWidth = Math.max(.8, radius * (.009 - index * .0016));
      ctx.beginPath();
      ctx.ellipse(centerX, centerY, ring, ring * (.49 + .08 * index),
        progress * 3.8 + index * .96, index * .9, tau - .45 + index * .9);
      ctx.stroke();
    }
  }

  function draw(now, hoverStep) {
    const collapse = scene.phase === 'collapse' ? clamp((now - scene.collapseAt) / collapseDuration) : 0;
    const scan = scene.phase === 'scan' ? clamp((now - scene.scanAt) / scanDuration) : 0;
    const opacity = 1 - ease(collapse);
    ctx.globalAlpha = 1;
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, width, height);
    drawStars();
    const longitude = .48 + 1.32 * Math.sin(.33 + (earthTime % 54) * tau / 54);
    const count = scene.phase !== 'idle' ? scene.count : form.hidden ? 0 : Math.min(maxMaskDots, password.value.length);
    if (atlas && radius > 0) {
      const editing = document.activeElement === password;
      const hoverTarget = scene.phase === 'idle' && (earthHovered || editing || earth.matches(':focus-visible')) ? 1 : 0;
      earthHighlight += (hoverTarget - earthHighlight) * hoverStep;
      const color = outlineColor(earthHighlight);
      drawCountries(longitude, color, opacity);
      ctx.globalAlpha = opacity;
      ctx.strokeStyle = color;
      ctx.lineWidth = Math.max(.83, radius * .016);
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius - ctx.lineWidth / 2, 0, tau);
      ctx.stroke();
    }
    const positions = satellites.map(satellitePosition);
    for (const [index, position] of positions.entries()) {
      const target = satelliteHovered(position) ? 1 : 0;
      satelliteHighlights[index] += (target - satelliteHighlights[index]) * hoverStep;
      drawSatellite(position, outlineColor(satelliteHighlights[index]), opacity);
    }
    drawMask(count, longitude, collapse);
    if (scan > 0 && !reducedMotion?.matches) drawScan(positions, scan);
    if (collapse > 0) drawBlackHole(collapse);
  }

  function requestFrame() {
    if (frame || document.hidden || screen.classList.contains('hidden')) return;
    frame = window.requestAnimationFrame(now => {
      frame = 0;
      if (document.hidden || screen.classList.contains('hidden')) {
        lastTime = 0;
        return;
      }
      const resting = reducedMotion?.matches;
      if (resting || !lastTime || now - lastTime >= 15) {
        const delta = !resting && lastTime ? Math.min(.075, (now - lastTime) / 1000) : 0;
        lastTime = now;
        elapsed += delta;
        if (scene.phase === 'idle' && !password.value.length) earthTime += delta;
        draw(now, resting || !delta ? 1 : Math.min(1, delta * 11));
      }
      if (!resting) requestFrame();
    });
  }

  // Decode the public, little-endian map using byte order explicitly.
  function decode(text, unsigned) {
    const raw = Uint8Array.from(atob(text), char => char.charCodeAt(0));
    const bytes = new DataView(raw.buffer);
    const values = unsigned ? new Uint16Array(raw.length / 2) : new Int16Array(raw.length / 2);
    for (let index = 0; index < values.length; index++) {
      values[index] = unsigned ? bytes.getUint16(index * 2, true) : bytes.getInt16(index * 2, true);
    }
    return values;
  }
  fetch('/icons/login-atlas.json').then(response => {
    if (!response.ok) throw new Error('EARTH_ATLAS_UNAVAILABLE');
    return response.json();
  }).then(data => {
    atlas = {points: decode(data.points), lines: decode(data.lines, true),
      slots: decode(data.slots), places: decode(data.places)};
    projected = new Float32Array(atlas.points.length);
    places = new Float32Array(atlas.places.length);
    screen.classList.add('login-atlas-ready');
    requestFrame();
  }).catch(() => {
    // The local static globe remains available when the atlas cannot load.
  });

  screen.addEventListener('pointermove', event => {
    if (event.pointerType === 'touch') return;
    pointer = {x: event.clientX, y: event.clientY};
    requestFrame();
  });
  screen.addEventListener('pointerleave', () => {
    pointer = null;
    requestFrame();
  });
  screen.addEventListener('focusin', requestFrame);
  screen.addEventListener('focusout', requestFrame);
  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', () => {
    lastTime = 0;
    requestFrame();
  });
  reducedMotion?.addEventListener?.('change', () => {
    lastTime = 0;
    requestFrame();
  });
  if ('ResizeObserver' in window) new ResizeObserver(resize).observe(screen);
  resize();
})();
