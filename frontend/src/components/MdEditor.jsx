import { useRef, useCallback, useState } from 'react';
import Icon from './Icon.jsx';
import MdPreview from './MdPreview.jsx';

const TOOLS = [
  [
    { id: 'h1',    label: 'H1',  title: 'Heading 1',   before: '# ',    after: '',   line: true },
    { id: 'h2',    label: 'H2',  title: 'Heading 2',   before: '## ',   after: '',   line: true },
    { id: 'h3',    label: 'H3',  title: 'Heading 3',   before: '### ',  after: '',   line: true },
  ],
  [
    { id: 'bold',   label: 'B',   title: 'Bold (Ctrl+B)',         before: '**', after: '**',  bold: true },
    { id: 'italic', label: 'I',   title: 'Italic (Ctrl+I)',       before: '_',  after: '_',   italic: true },
    { id: 'strike', label: 'S',   title: 'Strikethrough',         before: '~~', after: '~~',  strike: true },
  ],
  [
    { id: 'code',    label: '`',    title: 'Inline code (Ctrl+`)',  before: '`',     after: '`' },
    { id: 'codeblk', label: '```',  title: 'Code block',           before: '```\n', after: '\n```', block: true },
  ],
  [
    { id: 'link',  label: '🔗', title: 'Link (Ctrl+K)',    before: '[',     after: '](url)' },
    { id: 'ul',    label: '•',   title: 'List',             before: '- ',    after: '',   line: true },
    { id: 'ol',    label: '1.',  title: 'Ordered list',     before: '1. ',   after: '',   line: true },
    { id: 'task',  label: '☐',  title: 'Task list',        before: '- [ ] ', after: '', line: true },
    { id: 'quote', label: '❝',  title: 'Quote',            before: '> ',    after: '',   line: true },
  ],
  [
    { id: 'hr',    label: '─',  title: 'Divider',  before: '\n---\n', after: '' },
    { id: 'table', label: '⊞',  title: 'Table',    before: '| Column 1 | Column 2 | Column 3 |\n| --- | --- | --- |\n| Data | Data | Data |\n', after: '' },
  ],
];

function ToolBtn({ item, onInsert }) {
  const [hov, setHov] = useState(false);
  return (
    <button
      onClick={() => onInsert(item.before, item.after, item.line, item.block)}
      title={item.title}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        background: hov ? '#ffffff0e' : 'none',
        border: hov ? '1px solid #2a2d35' : '1px solid transparent',
        borderRadius: 4, padding: '3px 8px', cursor: 'pointer',
        color: hov ? '#e0e4ec' : '#808590',
        fontSize: 11, fontFamily: 'JetBrains Mono',
        fontWeight: item.bold ? 700 : 400,
        fontStyle: item.italic ? 'italic' : 'normal',
        textDecoration: item.strike ? 'line-through' : 'none',
        minWidth: 28, display: 'flex', alignItems: 'center', justifyContent: 'center',
        transition: 'all .1s',
      }}
    >
      {item.label}
    </button>
  );
}

function ViewToggle({ mode, setMode }) {
  const opts = [
    { id: 'edit', label: 'Edit' },
    { id: 'split', label: 'Split' },
    { id: 'preview', label: 'Preview' },
  ];
  return (
    <div style={{ display: 'flex', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, overflow: 'hidden' }}>
      {opts.map(o => (
        <button
          key={o.id}
          onClick={() => setMode(o.id)}
          style={{
            background: mode === o.id ? '#1e2029' : 'transparent',
            border: 'none', borderRight: o.id !== 'preview' ? '1px solid #2a2d35' : 'none',
            padding: '4px 12px', cursor: 'pointer',
            color: mode === o.id ? '#e0e4ec' : '#505560',
            fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: mode === o.id ? 600 : 400,
            transition: 'all .1s',
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export default function MdEditor({ value, onChange, accent, onUpload, uploading, onSave, onCancel, readOnly = false }) {
  const textRef = useRef();
  const [mode, setMode] = useState('split'); // 'edit' | 'split' | 'preview'

  const insert = useCallback((before, after = '', lineMode = false, blockMode = false) => {
    const ta = textRef.current;
    if (!ta) return;
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const sel = value.slice(start, end);

    let newText, newStart, newEnd;

    if (lineMode) {
      // Prepend to current line
      const lineStart = value.lastIndexOf('\n', start - 1) + 1;
      newText = value.slice(0, lineStart) + before + value.slice(lineStart);
      newStart = newEnd = start + before.length;
    } else if (blockMode) {
      // Wrap selection or insert block
      newText = value.slice(0, start) + before + sel + after + value.slice(end);
      newStart = start + before.length;
      newEnd = newStart + sel.length;
    } else {
      newText = value.slice(0, start) + before + sel + after + value.slice(end);
      newStart = start + before.length;
      newEnd = newStart + sel.length;
    }

    onChange(newText);
    requestAnimationFrame(() => {
      if (!textRef.current) return;
      textRef.current.focus();
      textRef.current.selectionStart = newStart;
      textRef.current.selectionEnd = newEnd;
    });
  }, [value, onChange]);

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      insert('  ');
    }
    if (e.key === 'Enter') {
      // Auto-continue lists
      const ta = textRef.current;
      const pos = ta.selectionStart;
      const lineStart = value.lastIndexOf('\n', pos - 1) + 1;
      const currentLine = value.slice(lineStart, pos);
      const listMatch = currentLine.match(/^(\s*)([-*]|\d+\.) /);
      const taskMatch = currentLine.match(/^(\s*)([-*]) \[[ x]\] /);
      if (taskMatch) {
        e.preventDefault();
        insert('\n' + taskMatch[1] + taskMatch[2] + ' [ ] ');
        return;
      }
      if (listMatch) {
        // If line is just the bullet, stop
        if (currentLine.trim() === listMatch[0].trim()) {
          e.preventDefault();
          onChange(value.slice(0, lineStart) + '\n' + value.slice(pos));
          requestAnimationFrame(() => { if (textRef.current) { textRef.current.selectionStart = textRef.current.selectionEnd = lineStart + 1; } });
          return;
        }
        e.preventDefault();
        const next = listMatch[2].match(/\d+/) ? `${parseInt(listMatch[2]) + 1}. ` : listMatch[2] + ' ';
        insert('\n' + listMatch[1] + next);
      }
    }
    if (e.ctrlKey || e.metaKey) {
      if (e.key === 'b') { e.preventDefault(); insert('**', '**'); }
      if (e.key === 'i') { e.preventDefault(); insert('_', '_'); }
      if (e.key === 'k') { e.preventDefault(); insert('[', '](url)'); }
      if (e.key === '`') { e.preventDefault(); insert('`', '`'); }
      if (e.key === 's') { e.preventDefault(); onSave?.(); }
    }
  }, [value, onChange, insert, onSave]);

  const handlePaste = useCallback(async (e) => {
    const items = Array.from(e.clipboardData?.items || []);
    const imageItem = items.find(it => it.type.startsWith('image/'));
    if (imageItem && onUpload) {
      e.preventDefault();
      const file = imageItem.getAsFile();
      if (file) await onUpload(file);
    }
  }, [onUpload]);

  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    if (!onUpload) return;
    const files = Array.from(e.dataTransfer.files);
    for (const file of files) await onUpload(file);
  }, [onUpload]);

  if (readOnly) {
    return (
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
        <MdPreview content={value} accent={accent} />
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 4, padding: '5px 14px',
        borderBottom: '1px solid #1e2029', background: '#080a0e', flexShrink: 0, flexWrap: 'wrap'
      }}>
        {TOOLS.map((group, gi) => (
          <div key={gi} style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {gi > 0 && <div style={{ width: 1, height: 16, background: '#2a2d35', margin: '0 4px' }} />}
            {group.map(item => <ToolBtn key={item.id} item={item} onInsert={insert} />)}
          </div>
        ))}
        <div style={{ width: 1, height: 16, background: '#2a2d35', margin: '0 4px' }} />
        {onUpload && (
          <label style={{
            background: 'none', border: `1px solid ${accent}55`, borderRadius: 4,
            padding: '3px 10px', cursor: uploading ? 'wait' : 'pointer',
            color: accent, fontSize: 10, fontFamily: 'JetBrains Mono',
            display: 'flex', alignItems: 'center', gap: 5, opacity: uploading ? 0.6 : 1,
            transition: 'opacity .1s',
          }}>
            <Icon name="export" size={10} color="currentColor" />
            {uploading ? 'Uploading...' : 'File'}
            <input
              type="file" style={{ display: 'none' }} multiple
              onChange={e => { Array.from(e.target.files || []).forEach(f => onUpload(f)); e.target.value = ''; }}
              disabled={uploading}
            />
          </label>
        )}
        <div style={{ flex: 1 }} />
        <ViewToggle mode={mode} setMode={setMode} />
        {onSave && (
          <>
            <button onClick={onSave} style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 14px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', marginLeft: 6 }}>
              Save
            </button>
            <button onClick={onCancel} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              Cancel
            </button>
          </>
        )}
      </div>

      {/* Editor / Preview area */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>
        {/* Textarea */}
        {(mode === 'edit' || mode === 'split') && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, borderRight: mode === 'split' ? '1px solid #1e2029' : 'none' }}>
            <textarea
              ref={textRef}
              value={value}
              onChange={e => onChange(e.target.value)}
              onKeyDown={handleKeyDown}
              onPaste={handlePaste}
              onDrop={handleDrop}
              onDragOver={e => e.preventDefault()}
              spellCheck={false}
              placeholder="Start typing markdown... Use toolbar or Ctrl+B / Ctrl+I / Ctrl+K"
              style={{
                flex: 1, width: '100%', background: '#09090d', border: 'none',
                outline: 'none', padding: '20px 24px', color: '#c8cdd6',
                fontSize: 13, fontFamily: 'JetBrains Mono', lineHeight: 1.8,
                resize: 'none', caretColor: accent, overflowY: 'auto',
              }}
            />
            <div style={{ padding: '4px 14px', borderTop: '1px solid #14161b', background: '#07080b', display: 'flex', justifyContent: 'flex-end', gap: 16, flexShrink: 0 }}>
              <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>
                {value.split('\n').length} lines · {value.length} chars
              </span>
            </div>
          </div>
        )}

        {/* Preview */}
        {(mode === 'preview' || mode === 'split') && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px', minWidth: 0, background: mode === 'split' ? '#090b0f' : 'transparent' }}>
            {mode === 'split' && (
              <div style={{ fontSize: 9, color: '#2a2d35', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', marginBottom: 12, letterSpacing: '0.1em' }}>Preview</div>
            )}
            <MdPreview content={value} accent={accent} />
          </div>
        )}
      </div>
    </div>
  );
}
