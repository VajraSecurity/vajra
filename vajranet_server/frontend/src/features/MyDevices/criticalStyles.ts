export const CRITICAL_CSS = `
.metallic-btn-critical {
  background: linear-gradient(135deg, rgba(220, 38, 38, 0.95) 0%, rgba(185, 28, 28, 1) 100%);
  color: white;
  border: 1px solid rgba(239, 68, 68, 0.4);
  border-bottom-color: rgba(153, 27, 27, 0.6);
  padding: 10px 20px;
  border-radius: 12px;
  font-weight: 600;
  box-shadow:
    0 2px 8px rgba(220, 38, 38, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.3),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  position: relative;
  overflow: hidden;
  backdrop-filter: blur(4px);
  transition: all 0.2s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.metallic-btn-critical.slate {
  background: linear-gradient(135deg, rgba(71, 85, 105, 0.95) 0%, rgba(51, 65, 85, 1) 100%);
  border: 1px solid rgba(100, 116, 139, 0.4);
  border-bottom-color: rgba(30, 41, 59, 0.6);
  box-shadow:
    0 2px 8px rgba(71, 85, 105, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.3),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
}

.metallic-btn-critical::before {
  content: '';
  position: absolute;
  top: 0;
  left: -150%;
  width: 150%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.5), transparent);
  transform: skewX(-20deg);
  animation: metallic-shimmer-critical 3.5s infinite;
}

@keyframes metallic-shimmer-critical {
  0% { left: -150%; }
  40% { left: 150%; }
  100% { left: 150%; }
}

.metallic-btn-critical:hover {
  box-shadow:
    0 4px 12px rgba(220, 38, 38, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.4),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  background: linear-gradient(135deg, rgba(239, 68, 68, 1) 0%, rgba(185, 28, 28, 1) 100%);
  transform: translateY(-1px);
}

.metallic-btn-critical.slate:hover {
  box-shadow:
    0 4px 12px rgba(71, 85, 105, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.4),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2);
  background: linear-gradient(135deg, rgba(100, 116, 139, 1) 0%, rgba(51, 65, 85, 1) 100%);
}

.metallic-btn-critical:active {
  transform: translateY(1px);
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.2),
    inset 0 2px 4px rgba(0, 0, 0, 0.3);
}

.metallic-btn-blue {
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.95) 0%, rgba(29, 78, 216, 1) 100%) !important;
  color: white !important;
  border-color: rgba(37, 99, 235, 0.4) !important;
  border-bottom-color: rgba(30, 58, 138, 0.6) !important;
  box-shadow:
    0 2px 8px rgba(37, 99, 235, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.35),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2) !important;
  position: relative;
  overflow: hidden;
  transition: all 0.2s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-blue:hover:not(:disabled) {
  box-shadow:
    0 4px 12px rgba(37, 99, 235, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.45),
    inset 0 -1px 1px rgba(0, 0, 0, 0.25) !important;
  background: linear-gradient(135deg, rgba(59, 130, 246, 1) 0%, rgba(37, 99, 235, 1) 100%) !important;
  transform: translateY(-1px);
}

.metallic-btn-blue:active:not(:disabled) {
  transform: translateY(1px) !important;
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.2),
    inset 0 2px 4px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-blue:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none !important;
}
`;
