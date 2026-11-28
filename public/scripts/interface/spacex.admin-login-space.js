'use strict';

(() => {
  const screen = document.getElementById('login-screen');
  const earth = document.getElementById('login-earth');
  const form = document.getElementById('login-form');
  const password = document.getElementById('login-password');
  const error = document.getElementById('login-error');
  const canvas = document.getElementById('login-space');
  if (!screen || !earth || !form || !password || !error || !canvas) return;

  function closeEditor(restoreFocus) {
    if (form.hidden) return;
    password.value = '';
    error.textContent = '';
    form.hidden = true;
    earth.setAttribute('aria-expanded', 'false');
    if (restoreFocus) earth.focus();
  }
  earth.addEventListener('click', () => {
    if (!form.hidden) {
      password.focus();
      return;
    }
    form.hidden = false;
    earth.setAttribute('aria-expanded', 'true');
    password.focus();
  });
  screen.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || form.hidden || event.isComposing) return;
    event.preventDefault();
    closeEditor(true);
  });
  const ctx = canvas.getContext('2d', {alpha: false});
  new MutationObserver(() => {
    if (screen.classList.contains('hidden')) closeEditor(false);
    if (ctx) requestFrame();
  }).observe(screen, {attributeFilter: ['class']});

  if (!ctx) return;
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  const tau = 2 * Math.PI;
  const borderInk = '#303239';
  const starInk = '#a7b6cd';
  const satellites = [
    {period: 12, offset: -.56, distance: 1.22},
    {period: 16.1, offset: 1.68, distance: 1.32},
    {period: 20.4, offset: 3.63, distance: 1.42}
  ];
  let width = 0, height = 0, centerX = 0, centerY = 0, radius = 0;
  let stars = [], atlas, projected, places;
  let frame = 0, lastTime = 0, elapsed = 0, earthTime = 0;
  let maskCount = 0, maskPoints = [], maskStarted = -1, maskFrom = 0;

  function seed(value) {
    value = Math.imul(value ^ (value >>> 16), 0x7feb352d);
    value = Math.imul(value ^ (value >>> 15), 0x846ca68b);
    return ((value ^ (value >>> 16)) & 65535) / 65535;
  }
  const detailStars = Array.from({length: 99}, (_, index) => {
    const id = 131 + index * 7;
    return { x: ((index % 9) + .14 + .72 * seed(id)) / 4.5 - 1,
      y: (Math.floor(index / 9) + .14 + .72 * seed(id + 1)) / 5.5 - 1,
      phase: tau * seed(id + 2), bright: index % 19 === 7 };
  }).filter(({x, y}) => x * x + y * y <= .875);

  function resize() {
    if (screen.classList.contains('hidden')) return;
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    if (!width || !height) return;
    const scale = Math.min(2, window.devicePixelRatio || 1);
    const surface = canvas.getBoundingClientRect();
    const planet = earth.getBoundingClientRect();
    centerX = planet.left - surface.left + planet.width / 2;
    centerY = planet.top - surface.top + planet.height / 2;
    radius = planet.width / 2;
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    ctx.setTransform(scale, 0, 0, scale, 0, 0);
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

  function shoreline(x, y, depth, otherX, otherY, otherDepth) {
    const t = depth / (depth - otherDepth);
    const horizonX = x + (otherX - x) * t;
    const horizonY = y + (otherY - y) * t;
    const inverse = 1 / (Math.hypot(horizonX, horizonY) || 1);
    return [horizonX * inverse, horizonY * inverse];
  }

  function drawCountries(longitude) {
    project(atlas.points, projected, longitude);
    ctx.globalAlpha = .92;
    ctx.strokeStyle = borderInk;
    ctx.lineWidth = Math.max(.65, radius * .0083);
    ctx.lineCap = 'round';
    ctx.beginPath();
    for (let index = 0; index < atlas.lines.length; index += 2) {
      const a = atlas.lines[index] * 3, b = atlas.lines[index + 1] * 3;
      let ax = projected[a], ay = projected[a + 1], bx = projected[b], by = projected[b + 1];
      const az = projected[a + 2], bz = projected[b + 2];
      if (az < 0 && bz < 0) continue;
      if (az < 0) [ax, ay] = shoreline(ax, ay, az, bx, by, bz);
      if (bz < 0) [bx, by] = shoreline(bx, by, bz, ax, ay, az);
      ctx.moveTo(centerX + ax * radius, centerY + ay * radius);
      ctx.lineTo(centerX + bx * radius, centerY + by * radius);
    }
    ctx.stroke();
    project(atlas.places, places, longitude);
    for (let index = 0; index < places.length; index += 3) {
      if (places[index + 2] < .12) continue;
      dot(centerX + places[index] * radius, centerY + places[index + 1] * radius,
        Math.max(.65, Math.min(2, radius * .0085)), .9, borderInk);
    }
  }

  function drawSatellite({period, offset, distance}) {
    const angle = offset + (elapsed % period) * tau / period;
    const sine = Math.sin(angle), cosine = Math.cos(angle);
    const size = radius * .084;
    ctx.save();
    ctx.transform(-sine * size, cosine * size, cosine * size, sine * size,
      centerX + cosine * radius * distance, centerY + sine * radius * distance);
    ctx.strokeStyle = borderInk;
    ctx.lineWidth = Math.max(.13, .77 / size);
    ctx.globalAlpha = .85;
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
    dot(0, 0, .081, .65);
    dot(0, -.61, .081, .55 + .45 * Math.max(0, Math.cos(elapsed * tau / 2.6)));
    for (const side of [-1, 1]) {
      dot(side * .69, .03, .071, .59);
      dot(side * 1.22, -.04, .055, .46);
    }
    ctx.restore();
  }

  function buildMaskLayout(longitude) {
    const coordinates = new Float32Array(atlas.slots.length);
    project(atlas.slots, coordinates, longitude);
    const candidates = [];
    for (let index = 0; index < coordinates.length; index += 3) {
      if (coordinates[index + 2] < .49) continue;
      const x = coordinates[index], y = coordinates[index + 1];
      candidates.push({x, y, distance: 1 - .70 * (x * x + y * y)});
    }
    const selected = [];
    for (let count = 0; count < 48 && candidates.length; count++) {
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

  function drawMask(count, longitude) {
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
    const visible = Math.min(count, maskPoints.length);
    for (let index = 0; index < visible; index++) {
      const {x, y} = maskPoints[index];
      const fade = reducedMotion?.matches || index < maskFrom
        ? 1 : Math.max(0, Math.min(1, (elapsed - maskStarted - (index - maskFrom) * .023) / .22));
      if (fade > 0) dot(centerX + x * radius, centerY + y * radius,
        Math.max(1.65, radius * .014) * (.55 + .45 * fade), fade * .94);
    }
  }

  function draw() {
    ctx.globalAlpha = 1;
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, width, height);
    drawStars();
    if (!atlas) return;
    const longitude = .48 + 1.32 * Math.sin(.33 + (earthTime % 54) * tau / 54);
    drawCountries(longitude);
    ctx.globalAlpha = 1;
    ctx.strokeStyle = borderInk;
    ctx.lineWidth = Math.max(.83, radius * .016);
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius - ctx.lineWidth / 2, 0, tau);
    ctx.stroke();
    for (const satellite of satellites) drawSatellite(satellite);
    drawMask(form.hidden ? 0 : Math.min(48, password.value.length), longitude);
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
      if (resting || !lastTime || now - lastTime >= 31) {
        const delta = !resting && lastTime ? Math.min(.075, (now - lastTime) / 1000) : 0;
        lastTime = now;
        elapsed += delta;
        if (form.hidden || !password.value.length) earthTime += delta;
        draw();
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

  password.addEventListener('input', requestFrame);
  screen.addEventListener('focusin', requestFrame);
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
