/**
 * ARAGOS v3.0 — Interactive Three.js 3D Cyber-Reconnaissance Background Engine
 * Supports 3 switchable 3D scenes (Orbital Recon Core, Neural Mesh Matrix, Quantum Torus)
 * and real-time state reactivity during module scans and AI inference.
 */
(function () {
  class AragosThreeBackground {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas || typeof THREE === "undefined") {
        console.warn("ARAGOS 3D: Canvas or THREE not available.");
        return;
      }

      this.mode = "globe"; // 'globe' | 'neural' | 'torus'
      this.state = "idle"; // 'idle' | 'scanning' | 'beast' | 'ai'
      this.mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
      this.clock = new THREE.Clock();
      this.speedMultiplier = 1.0;
      this.targetSpeedMultiplier = 1.0;

      this.initEngine();
      this.buildSceneObjects();
      this.bindEvents();
      this.animate();
    }

    initEngine() {
      this.scene = new THREE.Scene();
      this.scene.fog = new THREE.FogExp2(0x040711, 0.018);

      this.camera = new THREE.PerspectiveCamera(
        55,
        window.innerWidth / window.innerHeight,
        0.1,
        1000
      );
      this.camera.position.set(0, 2, 28);

      this.renderer = new THREE.WebGLRenderer({
        canvas: this.canvas,
        antialias: true,
        alpha: true,
        powerPreference: "high-performance",
      });
      this.renderer.setSize(window.innerWidth, window.innerHeight);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      this.renderer.setClearColor(0x040711, 1);

      // Ambient + Point Lights
      const ambient = new THREE.AmbientLight(0x1e293b, 1.8);
      this.scene.add(ambient);

      this.primaryLight = new THREE.PointLight(0x00f0ff, 3.5, 90);
      this.primaryLight.position.set(16, 14, 18);
      this.scene.add(this.primaryLight);

      this.secondaryLight = new THREE.PointLight(0x7c3aed, 3.2, 90);
      this.secondaryLight.position.set(-18, -12, 14);
      this.scene.add(this.secondaryLight);

      this.accentLight = new THREE.PointLight(0x10b981, 2.0, 70);
      this.accentLight.position.set(0, 18, -15);
      this.scene.add(this.accentLight);

      this.rootGroup = new THREE.Group();
      // Offset slightly right so the 3D core frames beautifully behind the glass workspace
      this.rootGroup.position.set(3.5, 0.5, 0);
      this.scene.add(this.rootGroup);
    }

    buildSceneObjects() {
      // Clear previous groups
      while (this.rootGroup.children.length > 0) {
        const obj = this.rootGroup.children[0];
        this.rootGroup.remove(obj);
      }

      this.globeGroup = new THREE.Group();
      this.neuralGroup = new THREE.Group();
      this.torusGroup = new THREE.Group();

      this.buildStarfield();
      this.buildOrbitalGlobe();
      this.buildNeuralMatrix();
      this.buildQuantumTorus();

      this.rootGroup.add(this.globeGroup);
      this.rootGroup.add(this.neuralGroup);
      this.rootGroup.add(this.torusGroup);

      this.applySceneVisibility();
    }

    buildStarfield() {
      const count = 1600;
      const positions = new Float32Array(count * 3);
      const colors = new Float32Array(count * 3);

      const cCyan = new THREE.Color(0x00f0ff);
      const cViolet = new THREE.Color(0x8b5cf6);
      const cEmerald = new THREE.Color(0x10b981);

      for (let i = 0; i < count; i++) {
        const r = 18 + Math.random() * 65;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
        positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
        positions[i * 3 + 2] = r * Math.cos(phi);

        const pick = Math.random();
        const col = pick < 0.55 ? cCyan : pick < 0.85 ? cViolet : cEmerald;
        colors[i * 3] = col.r;
        colors[i * 3 + 1] = col.g;
        colors[i * 3 + 2] = col.b;
      }

      const geo = new THREE.BufferGeometry();
      geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
      geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));

      const mat = new THREE.PointsMaterial({
        size: 0.16,
        vertexColors: true,
        transparent: true,
        opacity: 0.72,
        blending: THREE.AdditiveBlending,
      });

      this.starField = new THREE.Points(geo, mat);
      this.scene.add(this.starField);
    }

    buildOrbitalGlobe() {
      // Outer Wireframe Geodesic Sphere
      const icoGeo = new THREE.IcosahedronGeometry(7.8, 3);
      const icoMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.16,
        blending: THREE.AdditiveBlending,
      });
      this.wireSphere = new THREE.Mesh(icoGeo, icoMat);
      this.globeGroup.add(this.wireSphere);

      // Inner Core Hologram Sphere
      const coreGeo = new THREE.SphereGeometry(5.6, 32, 32);
      const coreMat = new THREE.MeshPhongMaterial({
        color: 0x071326,
        emissive: 0x091d38,
        specular: 0x00f0ff,
        shininess: 60,
        transparent: true,
        opacity: 0.75,
      });
      this.innerCore = new THREE.Mesh(coreGeo, coreMat);
      this.globeGroup.add(this.innerCore);

      // Surface Recon Node Points on Sphere
      const nodeCount = 420;
      const nodePos = new Float32Array(nodeCount * 3);
      for (let i = 0; i < nodeCount; i++) {
        const phi = Math.acos(-1 + (2 * i) / nodeCount);
        const theta = Math.sqrt(nodeCount * Math.PI) * phi;
        const rad = 7.85;
        nodePos[i * 3] = rad * Math.cos(theta) * Math.sin(phi);
        nodePos[i * 3 + 1] = rad * Math.sin(theta) * Math.sin(phi);
        nodePos[i * 3 + 2] = rad * Math.cos(phi);
      }
      const nodeGeo = new THREE.BufferGeometry();
      nodeGeo.setAttribute("position", new THREE.BufferAttribute(nodePos, 3));
      const nodeMat = new THREE.PointsMaterial({
        color: 0x38bdf8,
        size: 0.19,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
      });
      this.globeNodes = new THREE.Points(nodeGeo, nodeMat);
      this.globeGroup.add(this.globeNodes);

      // 3 Gyroscopic Orbital Rings
      this.orbitalRings = [];
      const ringConfigs = [
        { radius: 10.6, tube: 0.045, color: 0x00f0ff, rx: 1.15, ry: 0.3, rz: 0.0 },
        { radius: 12.4, tube: 0.035, color: 0x8b5cf6, rx: 0.65, ry: -0.8, rz: 0.4 },
        { radius: 14.2, tube: 0.03, color: 0x10b981, rx: -0.9, ry: 0.4, rz: -0.5 },
      ];

      ringConfigs.forEach((rc) => {
        const rGeo = new THREE.TorusGeometry(rc.radius, rc.tube, 16, 120);
        const rMat = new THREE.MeshBasicMaterial({
          color: rc.color,
          transparent: true,
          opacity: 0.45,
          blending: THREE.AdditiveBlending,
        });
        const ring = new THREE.Mesh(rGeo, rMat);
        ring.rotation.set(rc.rx, rc.ry, rc.rz);
        this.globeGroup.add(ring);
        this.orbitalRings.push(ring);
      });

      // Telemetry Beacons (spikes radiating from the globe)
      this.beaconsGroup = new THREE.Group();
      for (let i = 0; i < 18; i++) {
        const phi = Math.random() * Math.PI;
        const theta = Math.random() * Math.PI * 2;
        const dir = new THREE.Vector3(
          Math.sin(phi) * Math.cos(theta),
          Math.sin(phi) * Math.sin(theta),
          Math.cos(phi)
        );
        const start = dir.clone().multiplyScalar(7.8);
        const end = dir.clone().multiplyScalar(9.2 + Math.random() * 1.8);
        const lineGeo = new THREE.BufferGeometry().setFromPoints([start, end]);
        const lineMat = new THREE.LineBasicMaterial({
          color: i % 2 === 0 ? 0x00f0ff : 0x10b981,
          transparent: true,
          opacity: 0.65,
        });
        this.beaconsGroup.add(new THREE.Line(lineGeo, lineMat));
      }
      this.globeGroup.add(this.beaconsGroup);
    }

    buildNeuralMatrix() {
      const nodeCount = 95;
      const pts = [];
      for (let i = 0; i < nodeCount; i++) {
        pts.push(
          new THREE.Vector3(
            (Math.random() - 0.5) * 26,
            (Math.random() - 0.5) * 18,
            (Math.random() - 0.5) * 16
          )
        );
      }

      const linePositions = [];
      for (let i = 0; i < nodeCount; i++) {
        for (let j = i + 1; j < nodeCount; j++) {
          const d = pts[i].distanceTo(pts[j]);
          if (d < 6.2) {
            linePositions.push(pts[i].x, pts[i].y, pts[i].z);
            linePositions.push(pts[j].x, pts[j].y, pts[j].z);
          }
        }
      }

      const lineGeo = new THREE.BufferGeometry();
      lineGeo.setAttribute("position", new THREE.Float32BufferAttribute(linePositions, 3));
      const lineMat = new THREE.LineBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.24,
        blending: THREE.AdditiveBlending,
      });
      this.neuralLines = new THREE.LineSegments(lineGeo, lineMat);
      this.neuralGroup.add(this.neuralLines);

      const pGeo = new THREE.BufferGeometry().setFromPoints(pts);
      const pMat = new THREE.PointsMaterial({
        color: 0xa855f7,
        size: 0.35,
        transparent: true,
        opacity: 0.9,
        blending: THREE.AdditiveBlending,
      });
      this.neuralNodes = new THREE.Points(pGeo, pMat);
      this.neuralGroup.add(this.neuralNodes);
    }

    buildQuantumTorus() {
      const knotGeo = new THREE.TorusKnotGeometry(6.2, 1.65, 180, 28, 2, 3);
      const knotMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.22,
        blending: THREE.AdditiveBlending,
      });
      this.torusMesh = new THREE.Mesh(knotGeo, knotMat);
      this.torusGroup.add(this.torusMesh);

      const innerKnotGeo = new THREE.TorusKnotGeometry(6.2, 1.68, 140, 20, 2, 3);
      const innerKnotMat = new THREE.PointsMaterial({
        color: 0x8b5cf6,
        size: 0.14,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending,
      });
      this.torusPoints = new THREE.Points(innerKnotGeo, innerKnotMat);
      this.torusGroup.add(this.torusPoints);
    }

    applySceneVisibility() {
      if (!this.globeGroup) return;
      this.globeGroup.visible = this.mode === "globe";
      this.neuralGroup.visible = this.mode === "neural";
      this.torusGroup.visible = this.mode === "torus";
    }

    setSceneMode(mode) {
      this.mode = mode;
      this.applySceneVisibility();
    }

    setScanState(state) {
      this.state = state || "idle";
      if (!this.wireSphere) return;

      if (this.state === "scanning") {
        this.targetSpeedMultiplier = 3.4;
        this.wireSphere.material.color.setHex(0x10b981);
        this.primaryLight.color.setHex(0x10b981);
      } else if (this.state === "beast") {
        this.targetSpeedMultiplier = 5.2;
        this.wireSphere.material.color.setHex(0xf43f5e);
        this.primaryLight.color.setHex(0xf43f5e);
      } else if (this.state === "ai") {
        this.targetSpeedMultiplier = 2.4;
        this.wireSphere.material.color.setHex(0xa855f7);
        this.primaryLight.color.setHex(0xa855f7);
      } else {
        this.targetSpeedMultiplier = 1.0;
        this.wireSphere.material.color.setHex(0x00f0ff);
        this.primaryLight.color.setHex(0x00f0ff);
      }
    }

    bindEvents() {
      window.addEventListener("mousemove", (e) => {
        this.mouse.targetX = (e.clientX / window.innerWidth - 0.5) * 2;
        this.mouse.targetY = (e.clientY / window.innerHeight - 0.5) * 2;
      });

      window.addEventListener("resize", () => {
        if (!this.camera || !this.renderer) return;
        this.camera.aspect = window.innerWidth / window.innerHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(window.innerWidth, window.innerHeight);
      });
    }

    animate() {
      requestAnimationFrame(() => this.animate());

      const dt = Math.min(this.clock.getDelta(), 0.1);
      const elapsed = this.clock.getElapsedTime();

      this.speedMultiplier += (this.targetSpeedMultiplier - this.speedMultiplier) * 0.06;
      const spd = dt * this.speedMultiplier;

      // Smooth mouse parallax
      this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.05;
      this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.05;

      this.rootGroup.rotation.y = this.mouse.x * 0.35;
      this.rootGroup.rotation.x = this.mouse.y * 0.22;

      if (this.starField) {
        this.starField.rotation.y += spd * 0.04;
        this.starField.rotation.x += spd * 0.015;
      }

      if (this.globeGroup && this.globeGroup.visible) {
        this.wireSphere.rotation.y += spd * 0.22;
        this.wireSphere.rotation.x += spd * 0.07;
        this.globeNodes.rotation.y -= spd * 0.16;
        this.beaconsGroup.rotation.y += spd * 0.22;

        const pulse = 1 + Math.sin(elapsed * 2.5 * this.speedMultiplier) * 0.03;
        this.wireSphere.scale.set(pulse, pulse, pulse);

        if (this.orbitalRings.length >= 3) {
          this.orbitalRings[0].rotation.z += spd * 0.45;
          this.orbitalRings[1].rotation.x -= spd * 0.35;
          this.orbitalRings[2].rotation.y += spd * 0.28;
        }
      }

      if (this.neuralGroup && this.neuralGroup.visible) {
        this.neuralGroup.rotation.y += spd * 0.18;
        this.neuralGroup.rotation.z = Math.sin(elapsed * 0.4) * 0.12;
      }

      if (this.torusGroup && this.torusGroup.visible) {
        this.torusMesh.rotation.y += spd * 0.28;
        this.torusMesh.rotation.x += spd * 0.14;
        this.torusPoints.rotation.y -= spd * 0.2;
      }

      this.renderer.render(this.scene, this.camera);
    }
  }

  window.addEventListener("DOMContentLoaded", () => {
    window.AragosThreeScene = new AragosThreeBackground("aragos-webgl-canvas");
  });
})();
