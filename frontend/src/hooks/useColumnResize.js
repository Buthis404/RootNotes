import { useMemo, useRef, useState } from 'react';

export function useColumnResize(defaults) {
  const [widths, setWidths] = useState(defaults);
  const dragState = useRef(null);

  const columns = useMemo(() => Object.keys(defaults), [defaults]);

  const startResize = (key, e) => {
    e.preventDefault();
    e.stopPropagation();
    dragState.current = {
      key,
      startX: e.clientX,
      startWidth: widths[key] || defaults[key] || 120,
    };

    const onMove = (moveEvent) => {
      if (!dragState.current) return;
      const { key: activeKey, startX, startWidth } = dragState.current;
      const nextWidth = Math.max(60, startWidth + (moveEvent.clientX - startX));
      setWidths(prev => ({ ...prev, [activeKey]: nextWidth }));
    };

    const onUp = () => {
      dragState.current = null;
      globalThis.removeEventListener('mousemove', onMove);
      globalThis.removeEventListener('mouseup', onUp);
    };

    globalThis.addEventListener('mousemove', onMove);
    globalThis.addEventListener('mouseup', onUp);
  };

  return { widths, startResize, columns };
}
