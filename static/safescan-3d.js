import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.164.1/build/three.module.js";

const canvas = document.getElementById("safeScanModel");
const showcase = document.querySelector(".spline-showcase");

if (canvas && showcase && !showcase.dataset.splineSrc?.trim()) {
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
  camera.position.set(0, 0.45, 7.2);

  const renderer = new THREE.WebGLRenderer({
    canvas,
    alpha: true,
    antialias: true,
    powerPreference: "high-performance"
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.24;

  const rig = new THREE.Group();
  scene.add(rig);

  const cursor = new THREE.Vector2(0, 0);
  const target = new THREE.Vector2(-0.14, 0.05);
  const phoneTarget = new THREE.Vector2(0, 0);
  let isDragging = false;
  let dragStart = null;
  let rigStart = null;
  let isHovering = false;

  function drawSolanaBars(ctx, x, y, width, height) {
    const colors = ["#8f5bff", "#58a6ff", "#1ff1a5"];
    const gap = height * 0.18;
    const barHeight = (height - gap * 2) / 3;
    colors.forEach((color, index) => {
      const top = y + index * (barHeight + gap);
      const skew = barHeight * 0.42;
      const gradient = ctx.createLinearGradient(x, top, x + width, top + barHeight);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, index === 0 ? "#48f1b7" : "#9d6cff");
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.moveTo(x + skew, top);
      ctx.lineTo(x + width, top);
      ctx.lineTo(x + width - skew, top + barHeight);
      ctx.lineTo(x, top + barHeight);
      ctx.closePath();
      ctx.fill();
    });
  }

  function createSolanaMobileScreenTexture() {
    const textureCanvas = document.createElement("canvas");
    textureCanvas.width = 640;
    textureCanvas.height = 1120;
    const ctx = textureCanvas.getContext("2d");

    ctx.fillStyle = "#020304";
    ctx.fillRect(0, 0, 640, 1120);

    const texture = new THREE.CanvasTexture(textureCanvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = 8;
    return texture;
  }

  function createSolanaBackTexture() {
    const textureCanvas = document.createElement("canvas");
    textureCanvas.width = 640;
    textureCanvas.height = 1120;
    const ctx = textureCanvas.getContext("2d");

    const bg = ctx.createLinearGradient(0, 0, 640, 1120);
    bg.addColorStop(0, "#176c70");
    bg.addColorStop(0.42, "#0b3444");
    bg.addColorStop(1, "#050506");
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, 640, 1120);

    const edgeGlow = ctx.createLinearGradient(0, 0, 640, 1120);
    edgeGlow.addColorStop(0, "rgba(106, 255, 224, 0.32)");
    edgeGlow.addColorStop(0.48, "rgba(21, 97, 107, 0.04)");
    edgeGlow.addColorStop(1, "rgba(0, 0, 0, 0.58)");
    ctx.fillStyle = edgeGlow;
    ctx.fillRect(0, 0, 640, 1120);

    ctx.save();
    ctx.translate(270, 840);
    ctx.globalAlpha = 0.78;
    ctx.fillStyle = "#020405";
    [
      [0, 0, 100],
      [-8, 24, 92],
      [0, 48, 100]
    ].forEach(([x, y, width]) => {
      const height = 12;
      const skew = 9;
      ctx.beginPath();
      ctx.moveTo(x + skew, y);
      ctx.lineTo(x + width, y);
      ctx.lineTo(x + width - skew, y + height);
      ctx.lineTo(x, y + height);
      ctx.closePath();
      ctx.fill();
    });
    ctx.restore();

    const texture = new THREE.CanvasTexture(textureCanvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = 8;
    return texture;
  }

  function createSeedVaultTexture() {
    const textureCanvas = document.createElement("canvas");
    textureCanvas.width = 768;
    textureCanvas.height = 448;
    const ctx = textureCanvas.getContext("2d");

    ctx.clearRect(0, 0, textureCanvas.width, textureCanvas.height);

    function fillSpacedText(text, x, y, spacingMultiplier) {
      let cursorX = x;
      [...text].forEach((letter) => {
        ctx.fillText(letter, cursorX, y);
        cursorX += ctx.measureText(letter).width * spacingMultiplier;
      });
    }

    function drawStickerPath() {
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(textureCanvas.width, 0);
      ctx.lineTo(textureCanvas.width, textureCanvas.height - 58);
      ctx.quadraticCurveTo(textureCanvas.width, textureCanvas.height, textureCanvas.width - 58, textureCanvas.height);
      ctx.lineTo(58, textureCanvas.height);
      ctx.quadraticCurveTo(0, textureCanvas.height, 0, textureCanvas.height - 58);
      ctx.lineTo(0, 0);
      ctx.closePath();
    }

    drawStickerPath();
    ctx.clip();

    ctx.fillStyle = "rgba(39, 42, 43, 0.9)";
    ctx.fillRect(0, 0, textureCanvas.width, textureCanvas.height);

    ctx.fillStyle = "rgba(2, 4, 5, 0.9)";
    ctx.font = "700 55px Arial, sans-serif";
    fillSpacedText("SEED VAULT", 124, 92, 1.15);

    ctx.strokeStyle = "rgba(2, 4, 5, 0.9)";
    ctx.lineWidth = 10;
    ctx.beginPath();
    ctx.arc(650, 92, 52.5, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(650, 92, 19.8, 0, Math.PI * 2);
    ctx.stroke();
    ctx.fillStyle = "rgba(2, 4, 5, 0.9)";
    ctx.beginPath();
    ctx.arc(650, 92, 9.9, 0, Math.PI * 2);
    ctx.fill();

    const texture = new THREE.CanvasTexture(textureCanvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = 8;
    return texture;
  }

  function roundedRectShape(width, height, radius) {
    const x = -width / 2;
    const y = -height / 2;
    const shape = new THREE.Shape();
    shape.moveTo(x + radius, y);
    shape.lineTo(x + width - radius, y);
    shape.quadraticCurveTo(x + width, y, x + width, y + radius);
    shape.lineTo(x + width, y + height - radius);
    shape.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
    shape.lineTo(x + radius, y + height);
    shape.quadraticCurveTo(x, y + height, x, y + height - radius);
    shape.lineTo(x, y + radius);
    shape.quadraticCurveTo(x, y, x + radius, y);
    return shape;
  }

  function edgeClippedShape(width, height, radius) {
    const x = -width / 2;
    const y = -height / 2;
    const shape = new THREE.Shape();
    shape.moveTo(x, y + height);
    shape.lineTo(x + width, y + height);
    shape.lineTo(x + width, y + radius);
    shape.quadraticCurveTo(x + width, y, x + width - radius, y);
    shape.lineTo(x + radius, y);
    shape.quadraticCurveTo(x, y, x, y + radius);
    shape.lineTo(x, y + height);
    shape.closePath();
    return shape;
  }

  function roundedPanel(width, height, radius, depth, material, bevelSize = 0.035) {
    const geometry = new THREE.ExtrudeGeometry(roundedRectShape(width, height, radius), {
      depth,
      bevelEnabled: true,
      bevelSegments: 8,
      bevelSize,
      bevelThickness: bevelSize,
      curveSegments: 18
    });
    geometry.center();
    return new THREE.Mesh(geometry, material);
  }

  function edgeClippedPanel(width, height, radius, depth, material, bevelSize = 0.035) {
    const geometry = new THREE.ExtrudeGeometry(edgeClippedShape(width, height, radius), {
      depth,
      bevelEnabled: true,
      bevelSegments: 8,
      bevelSize,
      bevelThickness: bevelSize,
      curveSegments: 18
    });
    geometry.center();
    return new THREE.Mesh(geometry, material);
  }

  function roundedFace(width, height, radius, material) {
    const geometry = new THREE.ShapeGeometry(roundedRectShape(width, height, radius), 24);
    return new THREE.Mesh(geometry, material);
  }

  function edgeClippedFace(width, height, radius, material) {
    const geometry = new THREE.ShapeGeometry(edgeClippedShape(width, height, radius), 24);
    return new THREE.Mesh(geometry, material);
  }

  const materials = {
    phone: new THREE.MeshPhysicalMaterial({
      color: 0x111927,
      metalness: 0.62,
      roughness: 0.22,
      clearcoat: 0.82,
      clearcoatRoughness: 0.18
    }),
    bevel: new THREE.MeshPhysicalMaterial({
      color: 0x1c2a3f,
      metalness: 0.78,
      roughness: 0.2
    }),
    glass: new THREE.MeshPhysicalMaterial({
      color: 0x0b1422,
      metalness: 0.1,
      roughness: 0.08,
      transmission: 0.22,
      transparent: true,
      opacity: 0.78,
      clearcoat: 1
    }),
    sagaScreen: new THREE.MeshBasicMaterial({
      map: createSolanaMobileScreenTexture()
    }),
    sagaBack: new THREE.MeshBasicMaterial({
      map: createSolanaBackTexture()
    }),
    qrLight: new THREE.MeshStandardMaterial({
      color: 0xf2fbff,
      emissive: 0x9ed9ff,
      emissiveIntensity: 0.1,
      roughness: 0.38
    }),
    qrAccent: new THREE.MeshStandardMaterial({
      color: 0x67f2c8,
      emissive: 0x28dca6,
      emissiveIntensity: 0.45,
      roughness: 0.22
    }),
    shield: new THREE.MeshPhysicalMaterial({
      color: 0x83ffe0,
      emissive: 0x1fd6a3,
      emissiveIntensity: 0.24,
      metalness: 0,
      roughness: 0.04,
      transmission: 0.34,
      transparent: true,
      opacity: 0.44,
      clearcoat: 1,
      side: THREE.DoubleSide
    }),
    scanGlass: new THREE.MeshBasicMaterial({ color: 0x67f2c8, transparent: true, opacity: 0 })
  };

  const logoBarMaterials = [
    new THREE.MeshStandardMaterial({ color: 0x8f5bff, emissive: 0x7d45ff, emissiveIntensity: 0.22, roughness: 0.18 }),
    new THREE.MeshStandardMaterial({ color: 0x58a6ff, emissive: 0x3c8dff, emissiveIntensity: 0.18, roughness: 0.18 }),
    new THREE.MeshStandardMaterial({ color: 0x1ff1a5, emissive: 0x14d98f, emissiveIntensity: 0.24, roughness: 0.18 })
  ];

  const phone = new THREE.Group();
  phone.rotation.set(-0.08, -0.28, -0.025);
  phone.position.set(-0.36, 0.58, 0.08);
  phone.userData.baseRotation = phone.rotation.clone();
  phone.userData.basePosition = phone.position.clone();
  rig.add(phone);

  const body = roundedPanel(1.72, 3.42, 0.24, 0.19, materials.phone, 0.035);
  body.castShadow = true;
  phone.add(body);

  const bevel = roundedPanel(1.84, 3.54, 0.28, 0.13, materials.bevel, 0.04);
  bevel.position.z = -0.04;
  phone.add(bevel);

  const backGlass = roundedFace(1.58, 3.2, 0.22, materials.sagaBack);
  backGlass.position.z = -0.126;
  backGlass.rotation.y = Math.PI;
  phone.add(backGlass);

  const backFeatureMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x07171d,
    metalness: 0.45,
    roughness: 0.18,
    clearcoat: 0.8
  });

  const lensGlassMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x03080d,
    emissive: 0x02090d,
    emissiveIntensity: 0.08,
    metalness: 0.12,
    roughness: 0.28,
    clearcoat: 0.72,
    clearcoatRoughness: 0.2,
    side: THREE.DoubleSide
  });

  const cameraMetalMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x124b58,
    metalness: 0.82,
    roughness: 0.14,
    clearcoat: 0.92,
    clearcoatRoughness: 0.1
  });

  function addRearLens(x, y, radius, raised = 0.035) {
    const lensZ = -0.186 - raised;
    const outerMaterial = new THREE.MeshBasicMaterial({
      color: 0x020405,
      side: THREE.DoubleSide,
      polygonOffset: true,
      polygonOffsetFactor: -2,
      polygonOffsetUnits: -2
    });
    const outer = new THREE.Mesh(
      new THREE.CircleGeometry(radius, 48),
      outerMaterial
    );
    outer.position.set(x, y, lensZ);
    outer.rotation.set(0, Math.PI, 0);
    outer.renderOrder = 6;
    phone.add(outer);

    const glass = new THREE.Mesh(new THREE.CircleGeometry(radius * 0.68, 40), lensGlassMaterial);
    glass.position.set(x, y, lensZ - 0.006);
    glass.rotation.set(0, Math.PI, 0);
    glass.renderOrder = 7;
    phone.add(glass);

    const highlight = new THREE.Mesh(
      new THREE.CircleGeometry(radius * 0.16, 18),
      new THREE.MeshBasicMaterial({
        color: 0x6ef8ff,
        transparent: true,
        opacity: 0.34,
        depthWrite: false,
        polygonOffset: true,
        polygonOffsetFactor: -4,
        polygonOffsetUnits: -4
      })
    );
    highlight.position.set(x - radius * 0.16, y + radius * 0.12, lensZ - 0.012);
    highlight.rotation.set(0, Math.PI, 0);
    highlight.renderOrder = 8;
    phone.add(highlight);
  }

  const topCameraHousing = new THREE.Mesh(
    new THREE.CylinderGeometry(0.17, 0.17, 0.024, 48),
    backFeatureMaterial
  );
  topCameraHousing.position.set(0.54, 1.48, -0.164);
  topCameraHousing.rotation.x = Math.PI / 2;
  phone.add(topCameraHousing);

  addRearLens(0.54, 1.48, 0.105, 0.024);

  const cameraIsland = roundedPanel(0.34, 0.82, 0.13, 0.024, backFeatureMaterial, 0.01);
  cameraIsland.position.set(0.54, 0.78, -0.164);
  cameraIsland.rotation.y = Math.PI;
  phone.add(cameraIsland);

  addRearLens(0.54, 1.0, 0.105, 0.024);
  addRearLens(0.54, 0.56, 0.105, 0.024);

  const flash = new THREE.Mesh(
    new THREE.CylinderGeometry(0.055, 0.055, 0.014, 28),
    new THREE.MeshBasicMaterial({ color: 0xb7f7e6, transparent: true, opacity: 0.68 })
  );
  flash.position.set(0.25, 1.29, -0.186);
  flash.rotation.x = Math.PI / 2;
  phone.add(flash);

  const moduleGroup = new THREE.Group();
  moduleGroup.position.set(0.64, -0.36, -0.166);
  moduleGroup.rotation.set(0, Math.PI, Math.PI / 2);
  phone.add(moduleGroup);

  const moduleFace = new THREE.Mesh(
    new THREE.PlaneGeometry(0.92, 0.54),
    new THREE.MeshBasicMaterial({
      map: createSeedVaultTexture(),
      transparent: true,
      alphaTest: 0.08,
      opacity: 0.78,
      side: THREE.DoubleSide
    })
  );
  moduleFace.position.z = 0.004;
  moduleGroup.add(moduleFace);

  const screen = roundedFace(1.68, 3.34, 0.23, materials.sagaScreen);
  screen.position.z = 0.103;
  phone.add(screen);

  const frontCamera = new THREE.Mesh(
    new THREE.CircleGeometry(0.032, 36),
    new THREE.MeshBasicMaterial({ color: 0x444b54, side: THREE.DoubleSide })
  );
  frontCamera.position.set(0, 1.48, 0.132);
  phone.add(frontCamera);

  const frontCameraRim = new THREE.Mesh(
    new THREE.RingGeometry(0.034, 0.04, 36),
    new THREE.MeshBasicMaterial({ color: 0x6d7680, transparent: true, opacity: 0.36, side: THREE.DoubleSide })
  );
  frontCameraRim.position.set(0, 1.48, 0.134);
  phone.add(frontCameraRim);

  const qr = new THREE.Group();
  qr.position.set(0, -0.08, 0.146);
  qr.scale.setScalar(0.66);
  phone.add(qr);

  const qrPattern = [
    1, 1, 1, 0, 1, 0, 1, 1,
    1, 0, 1, 0, 0, 1, 0, 1,
    1, 1, 1, 1, 0, 1, 1, 0,
    0, 0, 1, 0, 1, 1, 0, 1,
    1, 0, 0, 1, 1, 0, 1, 0,
    0, 1, 1, 0, 0, 1, 0, 1,
    1, 0, 1, 1, 1, 0, 1, 1,
    1, 1, 0, 0, 1, 1, 0, 1
  ];

  const qrDarkMaterial = new THREE.MeshStandardMaterial({
    color: 0x071011,
    emissive: 0x0c3f37,
    emissiveIntensity: 0.08,
    roughness: 0.18,
    metalness: 0.28
  });
  const qrTealMaterial = new THREE.MeshStandardMaterial({
    color: 0x67f2c8,
    emissive: 0x17b987,
    emissiveIntensity: 0.62,
    roughness: 0.12,
    metalness: 0.18
  });
  const qrActiveMaterials = [];
  const tileGeometry = new THREE.BoxGeometry(0.11, 0.11, 0.014);
  qrPattern.forEach((active, index) => {
    if (!active) return;
    const activeMaterial = qrTealMaterial.clone();
    activeMaterial.emissiveIntensity = index % 7 === 0 ? 0.62 : 0.12;
    activeMaterial.opacity = index % 7 === 0 ? 1 : 0.72;
    activeMaterial.transparent = index % 7 !== 0;
    qrActiveMaterials.push(activeMaterial);
    const tile = new THREE.Mesh(tileGeometry, activeMaterial);
    tile.position.set((index % 8 - 3.5) * 0.14, (3.5 - Math.floor(index / 8)) * 0.14, 0);
    tile.userData.baseZ = tile.position.z;
    tile.userData.baseIntensity = activeMaterial.emissiveIntensity;
    qr.add(tile);
  });

  const beam = new THREE.Mesh(
    new THREE.PlaneGeometry(1.5, 0.032),
    new THREE.MeshBasicMaterial({
      color: 0x67f2c8,
      transparent: true,
      opacity: 0.5,
      blending: THREE.AdditiveBlending,
      side: THREE.DoubleSide,
      depthWrite: false
    })
  );
  beam.position.set(0, 0.5, 0.006);
  qr.add(beam);

  const particleGeometry = new THREE.BufferGeometry();
  const particleCount = 520;
  const positions = new Float32Array(particleCount * 3);
  const particleColors = new Float32Array(particleCount * 3);
  const starColor = new THREE.Color();
  function randomStarY(index) {
    return index < 150
      ? 1.45 + Math.random() * 2.6
      : (Math.random() - 0.44) * 6.8;
  }
  for (let i = 0; i < particleCount; i += 1) {
    positions[i * 3] = (Math.random() - 0.5) * 7.2;
    positions[i * 3 + 1] = randomStarY(i);
    positions[i * 3 + 2] = -2.3 - Math.random() * 1.2;
    const brightness = 0.5;
    starColor.setRGB(0.78 * brightness, 0.9 * brightness, brightness);
    particleColors[i * 3] = starColor.r;
    particleColors[i * 3 + 1] = starColor.g;
    particleColors[i * 3 + 2] = starColor.b;
  }
  particleGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  particleGeometry.setAttribute("color", new THREE.BufferAttribute(particleColors, 3));
  const particles = new THREE.Points(
    particleGeometry,
    new THREE.PointsMaterial({
      size: 0.014,
      transparent: true,
      opacity: 0.82,
      depthTest: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      vertexColors: true
    })
  );
  scene.add(particles);

  const brightParticleGeometry = new THREE.BufferGeometry();
  const brightParticleCount = Math.round(particleCount * 0.1);
  const brightPositions = new Float32Array(brightParticleCount * 3);
  for (let i = 0; i < brightParticleCount; i += 1) {
    brightPositions[i * 3] = (Math.random() - 0.5) * 7.2;
    brightPositions[i * 3 + 1] = randomStarY(i);
    brightPositions[i * 3 + 2] = -2.35 - Math.random() * 1.15;
  }
  brightParticleGeometry.setAttribute("position", new THREE.BufferAttribute(brightPositions, 3));
  const brightParticles = new THREE.Points(
    brightParticleGeometry,
    new THREE.PointsMaterial({
      color: 0xffffff,
      size: 0.032,
      transparent: true,
      opacity: 1,
      depthTest: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending
    })
  );
  scene.add(brightParticles);

  const keyLight = new THREE.DirectionalLight(0xffffff, 3.05);
  keyLight.position.set(2.8, 3.4, 4);
  scene.add(keyLight);
  scene.add(new THREE.AmbientLight(0x8bb8ff, 1.05));

  const accentLight = new THREE.PointLight(0x67f2c8, 9.6, 8.6);
  accentLight.position.set(1.9, 0.5, 2.4);
  scene.add(accentLight);

  function resize() {
    const bounds = canvas.getBoundingClientRect();
    const width = Math.max(1, bounds.width);
    const height = Math.max(1, bounds.height);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
  }

  function setPointer(event) {
    const bounds = showcase.getBoundingClientRect();
    cursor.x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 2;
    cursor.y = -((event.clientY - bounds.top) / bounds.height - 0.5) * 2;
    if (!isDragging) {
      target.x = cursor.x * 0.34 - 0.14;
      target.y = cursor.y * 0.22 + 0.05;
      phoneTarget.x = cursor.x;
      phoneTarget.y = cursor.y;
    }
  }

  showcase.addEventListener("pointerenter", () => {
    isHovering = true;
  });

  showcase.addEventListener("pointermove", (event) => {
    setPointer(event);
    if (!isDragging || !dragStart || !rigStart) return;
    target.x = rigStart.x + (event.clientX - dragStart.x) * 0.008;
    target.y = rigStart.y + (event.clientY - dragStart.y) * 0.004;
    phoneTarget.x = target.x * 1.8;
    phoneTarget.y = target.y * 1.8;
  });

  showcase.addEventListener("pointerdown", (event) => {
    isDragging = true;
    dragStart = { x: event.clientX, y: event.clientY };
    rigStart = { x: target.x, y: target.y };
    showcase.setPointerCapture(event.pointerId);
  });

  showcase.addEventListener("pointerup", (event) => {
    isDragging = false;
    showcase.releasePointerCapture(event.pointerId);
  });

  showcase.addEventListener("pointerleave", () => {
    isHovering = false;
    isDragging = false;
    target.x = -0.14;
    target.y = 0.05;
    phoneTarget.x = 0;
    phoneTarget.y = 0;
  });

  new ResizeObserver(resize).observe(showcase);
  resize();
  showcase.classList.add("webgl-ready");

  const clock = new THREE.Clock();
  function animate() {
    const time = clock.getElapsedTime();
    rig.rotation.y += (target.x - rig.rotation.y) * 0.055;
    rig.rotation.x += (target.y - rig.rotation.x) * 0.055;
    const hoverLift = isHovering ? 0.08 : 0;
    const desiredPhoneY = phone.userData.basePosition.y + hoverLift + Math.sin(time * 1.1) * 0.055;
    const desiredPhoneZ = phone.userData.basePosition.z + (isHovering ? 0.18 : 0);
    phone.position.y += (desiredPhoneY - phone.position.y) * 0.08;
    phone.position.z += (desiredPhoneZ - phone.position.z) * 0.08;
    phone.rotation.y += (phone.userData.baseRotation.y + phoneTarget.x * 0.24 - phone.rotation.y) * 0.08;
    phone.rotation.x += (phone.userData.baseRotation.x - phoneTarget.y * 0.16 - phone.rotation.x) * 0.08;
    phone.rotation.z += (phone.userData.baseRotation.z - phoneTarget.x * 0.035 - phone.rotation.z) * 0.08;
    particles.rotation.z = Math.sin(time * 0.08) * 0.025;
    brightParticles.rotation.z = particles.rotation.z;
    beam.position.y = 0.5 - (time * 0.45 % 1);
    beam.material.opacity = 0.4 + Math.sin(time * 7) * 0.12;
    qr.children.forEach((tile, index) => {
      if (!tile.userData || typeof tile.userData.baseZ !== "number") return;
      const lightResponse = Math.min(1.1, Math.max(0, Math.abs(phone.rotation.y - phone.userData.baseRotation.y)) * 3.2);
      const shimmer = (Math.sin(time * 5.2 + index * 0.67) + 1) * 0.5;
      const targetIntensity = Math.max(tile.userData.baseIntensity, 0.78 + lightResponse * 1.15 + shimmer * 0.16);
      tile.material.emissiveIntensity = targetIntensity;
      tile.material.opacity = Math.min(1, 0.72 + lightResponse * 0.32 + shimmer * 0.06);
      tile.position.z = tile.userData.baseZ + Math.sin(time * 1.8 + index * 0.31) * 0.007;
    });
    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  }

  animate();
}
