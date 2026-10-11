import { useEffect, useRef } from 'react';

export default function MatrixBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    let animFrame;
    let W, H;
    let cols, drops, speeds, opacities, layers;

    const CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const FONT_SIZE = 13;
    const NUM_LAYERS = 3;

    function init() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols = Math.floor(W / FONT_SIZE);

      drops = [];
      speeds = [];
      opacities = [];
      layers = [];

      for (let i = 0; i < cols * NUM_LAYERS; i++) {
        drops.push(Math.random() * -H / FONT_SIZE);
        speeds.push(0.3 + Math.random() * 0.7);
        opacities.push(0.05 + Math.random() * 0.15);
        layers.push(Math.floor(i / cols));
      }
    }

    function draw() {
      // Fade trail
      ctx.fillStyle = 'rgba(2, 8, 16, 0.05)';
      ctx.fillRect(0, 0, W, H);

      for (let i = 0; i < drops.length; i++) {
        const layerIdx = layers[i];
        const colIdx = i % cols;
        const x = colIdx * FONT_SIZE;
        const y = drops[i] * FONT_SIZE;
        const char = CHARS[Math.floor(Math.random() * CHARS.length)];

        const depthScale = 1 - layerIdx * 0.25;
        const baseOpacity = opacities[i] * depthScale;

        // Head glow
        const headGrad = ctx.createLinearGradient(x, y - FONT_SIZE * 3, x, y + FONT_SIZE);
        headGrad.addColorStop(0, `rgba(0, 240, 255, 0)`);
        headGrad.addColorStop(0.7, `rgba(0, 240, 255, ${baseOpacity * 4})`);
        headGrad.addColorStop(1, `rgba(180, 255, 255, ${baseOpacity * 8})`);

        ctx.font = `${FONT_SIZE * depthScale}px 'Space Mono', monospace`;
        ctx.fillStyle = headGrad;
        ctx.shadowColor = '#00f0ff';
        ctx.shadowBlur = layerIdx === 0 ? 6 : 2;
        ctx.fillText(char, x, y);
        ctx.shadowBlur = 0;

        // Trailing chars
        for (let t = 1; t < 6; t++) {
          const ty = y - t * FONT_SIZE * depthScale;
          const trailOpacity = baseOpacity * (1 - t / 6);
          ctx.fillStyle = `rgba(0, 200, 220, ${trailOpacity})`;
          ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], x, ty);
        }

        // Reset
        if (drops[i] * FONT_SIZE > H && Math.random() > 0.975) {
          drops[i] = Math.random() * -20;
        }
        drops[i] += speeds[i];
      }

      animFrame = requestAnimationFrame(draw);
    }

    init();
    draw();

    const handleResize = () => { init(); };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animFrame);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0, left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        opacity: 0.65,
        pointerEvents: 'none',
      }}
    />
  );
}
