/**
 * A compact, always-idle-safe "thinking" orb: a breathing gradient core
 * wrapped in two counter-rotating plasma rings and two orbiting motes, all
 * pure CSS (keyframes live in index.css under "Floating chat widget:
 * thinking orb" — `orb-breathe`/`orb-spin`/`orb-glow`/`orb-orbit`) so it
 * costs nothing beyond a few composited layers and needs no animation
 * library. Distinct from the AI page's `AuroraThinking` (two plain ping
 * circles) — this is the floating widget's launcher idle-state and
 * "thinking" indicator, sized up or down via `size`.
 */
export default function ThinkingOrb({ size = 20, className = '' }: { size?: number; className?: string }) {
  return (
    <span
      className={`relative inline-block shrink-0 ${className}`}
      style={{ width: size, height: size }}
      aria-hidden="true"
    >
      <span
        className="orb-glow absolute inset-0 rounded-full blur-[3px]"
        style={{ background: 'radial-gradient(circle, rgba(192,132,252,0.6) 0%, rgba(129,140,248,0.35) 45%, transparent 72%)' }}
      />
      <span
        className="orb-ring-slow absolute inset-0 rounded-full"
        style={{
          background: 'conic-gradient(from 0deg, #c084fc, #818cf8, #8F407F, #c084fc)',
          WebkitMaskImage: 'radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 calc(100% - 1.5px))',
          maskImage: 'radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 calc(100% - 1.5px))',
        }}
      />
      <span
        className="orb-ring absolute rounded-full"
        style={{
          inset: '16%',
          background: 'conic-gradient(from 90deg, #818cf8, #c084fc, #e9d5ff, #818cf8)',
          WebkitMaskImage: 'radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 calc(100% - 1.5px))',
          maskImage: 'radial-gradient(farthest-side, transparent calc(100% - 1.5px), #000 calc(100% - 1.5px))',
          opacity: 0.85,
        }}
      />
      <span
        className="orb-core absolute rounded-full"
        style={{
          inset: '30%',
          background: 'radial-gradient(circle at 35% 30%, #f3e8ff 0%, #c084fc 42%, #818cf8 78%, #6d28d9 100%)',
          boxShadow: '0 0 8px rgba(192,132,252,0.85)',
        }}
      />
      <span className="orb-orbit-a absolute inset-0">
        <span
          className="absolute rounded-full"
          style={{ width: '14%', height: '14%', top: '2%', left: '50%', transform: 'translateX(-50%)', background: '#f3e8ff', boxShadow: '0 0 4px rgba(243,232,255,0.9)' }}
        />
      </span>
      <span className="orb-orbit-b absolute inset-0">
        <span
          className="absolute rounded-full"
          style={{ width: '10%', height: '10%', bottom: '4%', left: '50%', transform: 'translateX(-50%)', background: '#818cf8' }}
        />
      </span>
    </span>
  );
}
