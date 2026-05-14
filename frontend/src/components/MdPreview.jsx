import { useState, useCallback } from 'react';
import DOMPurify from 'dompurify';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import hljs from 'highlight.js/lib/core';
import { downloadUrl } from '../api.js';

// Languages for syntax highlighting
import langBash from 'highlight.js/lib/languages/bash';
import langPython from 'highlight.js/lib/languages/python';
import langJavaScript from 'highlight.js/lib/languages/javascript';
import langTypeScript from 'highlight.js/lib/languages/typescript';
import langPowershell from 'highlight.js/lib/languages/powershell';
import langSQL from 'highlight.js/lib/languages/sql';
import langXML from 'highlight.js/lib/languages/xml';
import langJSON from 'highlight.js/lib/languages/json';
import langGo from 'highlight.js/lib/languages/go';
import langRuby from 'highlight.js/lib/languages/ruby';
import langC from 'highlight.js/lib/languages/c';
import langCpp from 'highlight.js/lib/languages/cpp';
import langCsharp from 'highlight.js/lib/languages/csharp';
import langJava from 'highlight.js/lib/languages/java';
import langPHP from 'highlight.js/lib/languages/php';
import langYAML from 'highlight.js/lib/languages/yaml';
import langNginx from 'highlight.js/lib/languages/nginx';
import langMarkdown from 'highlight.js/lib/languages/markdown';
import langPerl from 'highlight.js/lib/languages/perl';
import langRust from 'highlight.js/lib/languages/rust';

hljs.registerLanguage('bash', langBash);
hljs.registerLanguage('sh', langBash);
hljs.registerLanguage('shell', langBash);
hljs.registerLanguage('python', langPython);
hljs.registerLanguage('py', langPython);
hljs.registerLanguage('javascript', langJavaScript);
hljs.registerLanguage('js', langJavaScript);
hljs.registerLanguage('typescript', langTypeScript);
hljs.registerLanguage('ts', langTypeScript);
hljs.registerLanguage('powershell', langPowershell);
hljs.registerLanguage('ps1', langPowershell);
hljs.registerLanguage('sql', langSQL);
hljs.registerLanguage('xml', langXML);
hljs.registerLanguage('html', langXML);
hljs.registerLanguage('json', langJSON);
hljs.registerLanguage('go', langGo);
hljs.registerLanguage('ruby', langRuby);
hljs.registerLanguage('rb', langRuby);
hljs.registerLanguage('c', langC);
hljs.registerLanguage('cpp', langCpp);
hljs.registerLanguage('csharp', langCsharp);
hljs.registerLanguage('cs', langCsharp);
hljs.registerLanguage('java', langJava);
hljs.registerLanguage('php', langPHP);
hljs.registerLanguage('yaml', langYAML);
hljs.registerLanguage('yml', langYAML);
hljs.registerLanguage('nginx', langNginx);
hljs.registerLanguage('markdown', langMarkdown);
hljs.registerLanguage('md', langMarkdown);
hljs.registerLanguage('perl', langPerl);
hljs.registerLanguage('rust', langRust);
hljs.registerLanguage('rs', langRust);

const VIDEO_EXT = new Set(['mp4', 'webm', 'mov', 'avi', 'mkv', 'ogv']);
const AUDIO_EXT = new Set(['mp3', 'ogg', 'wav', 'flac', 'm4a', 'aac', 'opus']);
const IMAGE_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'avif']);
const CODE_EXT  = new Set(['py','js','ts','sh','bash','ps1','rb','go','java','c','cpp','cs','php','sql','json','xml','yaml','yml','toml','ini','conf','dockerfile','txt','md','rs','perl','pl','lua','r','m','swift','kt','scala','hs','ex','exs','clj','vim']);

function getExt(url = '') {
  return url.split('?')[0].split('.').pop().toLowerCase();
}

function CopyBtn({ text, accent }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);
  return (
    <button
      onClick={copy}
      style={{
        position: 'absolute', top: 8, right: 10, background: copied ? `${accent}22` : '#1a1c22',
        border: `1px solid ${copied ? accent : '#2a2d35'}`, borderRadius: 4,
        padding: '2px 8px', cursor: 'pointer', fontSize: 9, color: copied ? accent : '#606570',
        fontFamily: 'JetBrains Mono', zIndex: 1, transition: 'all .15s'
      }}
    >
      {copied ? '✓ copied' : 'copy'}
    </button>
  );
}

function LightboxImage({ src, alt }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <img
        src={src} alt={alt || ''}
        onClick={() => setOpen(true)}
        onError={e => { e.target.style.border = '1px solid #cc2233'; e.target.title = 'Failed to load'; }}
        style={{ maxWidth: '100%', maxHeight: 520, objectFit: 'contain', borderRadius: 8, border: '1px solid #2a2d35', display: 'block', margin: '10px 0', cursor: 'zoom-in', background: '#0d0f14' }}
      />
      {alt && <div style={{ fontSize: 10, color: '#505560', marginTop: -6, marginBottom: 10, fontStyle: 'italic' }}>{alt}</div>}
      {open && (
        <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999, cursor: 'zoom-out', backdropFilter: 'blur(4px)' }}>
          <img src={src} alt={alt || ''} style={{ maxWidth: '90vw', maxHeight: '90vh', objectFit: 'contain', borderRadius: 8, boxShadow: '0 0 60px #00000088' }} />
        </div>
      )}
    </>
  );
}

function VideoPlayer({ src, children }) {
  return (
    <div style={{ margin: '10px 0' }}>
      <video controls src={src} style={{ maxWidth: '100%', borderRadius: 8, border: '1px solid #2a2d35', display: 'block', background: '#000' }}>
        {children}
        Your browser does not support video. <a href={src} target="_blank" rel="noreferrer">Download</a>
      </video>
    </div>
  );
}

function AudioPlayer({ src }) {
  return (
    <div style={{ margin: '10px 0', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 8, padding: '10px 14px' }}>
      <audio controls src={src} style={{ width: '100%', height: 36 }} />
    </div>
  );
}

function PdfEmbed({ src, text }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{ margin: '10px 0', border: '1px solid #2a2d35', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 14px', background: '#0d0f14', borderBottom: expanded ? '1px solid #2a2d35' : 'none' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>📄</span>
          <a href={src} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: '#6fc8f0', fontFamily: 'JetBrains Mono', textDecoration: 'none' }}>{text || 'PDF document'}</a>
        </div>
        <button onClick={() => setExpanded(v => !v)} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {expanded ? 'Collapse' : 'Open'}
        </button>
      </div>
      {expanded && <iframe src={src} title={text} style={{ width: '100%', height: 560, border: 'none', display: 'block' }} />}
    </div>
  );
}

function FileLink({ href, children, accent }) {
  const ext = getExt(href);
  const isCode = CODE_EXT.has(ext);
  const icons = { zip: '🗜', tar: '🗜', gz: '🗜', '7z': '🗜', rar: '🗜', exe: '⚙', dll: '⚙', bin: '⚙', iso: '💿', txt: '📝', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊', csv: '📊', pptx: '📊' };
  const icon = isCode ? '📋' : (icons[ext] || '📎');
  const label = typeof children === 'string' ? children : (Array.isArray(children) ? children.join('') : String(children || ext));
  return (
    <a
      href={downloadUrl(href)} download
      style={{ display: 'inline-flex', alignItems: 'center', gap: 7, background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 6, padding: '5px 12px', color: accent || '#6fc8f0', fontSize: 11, fontFamily: 'JetBrains Mono', textDecoration: 'none', margin: '4px 0', transition: 'border-color .12s' }}
      onMouseEnter={e => e.currentTarget.style.borderColor = accent || '#6fc8f0'}
      onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}
    >
      <span>{icon}</span>
      <span>{label}</span>
      <span style={{ fontSize: 9, color: '#404550', marginLeft: 4 }}>.{ext}</span>
    </a>
  );
}

function buildComponents(accent) {
  return {
    // Inline code
    code({ node, inline, className, children, ...props }) {
      if (inline) {
        return (
          <code style={{ background: '#1a1c22', padding: '1px 6px', borderRadius: 3, fontSize: '0.88em', color: accent, fontFamily: 'JetBrains Mono', wordBreak: 'break-word' }}>
            {children}
          </code>
        );
      }
      // Block code
      const lang = (className || '').replace('language-', '').trim();
      const code = String(children).replace(/\n$/, '');
      let highlighted = code;
      try {
        if (lang && hljs.getLanguage(lang)) {
          highlighted = hljs.highlight(code, { language: lang }).value;
        } else if (code.length < 20000) {
          const res = hljs.highlightAuto(code);
          highlighted = res.value;
        }
      } catch {}
      return (
        <div style={{ position: 'relative', margin: '14px 0' }}>
          {lang && (
            <div style={{ position: 'absolute', top: 10, left: 14, fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.1em', userSelect: 'none' }}>
              {lang}
            </div>
          )}
          <CopyBtn text={code} accent={accent} />
          <pre style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: lang ? '32px 16px 14px' : '14px 16px', overflowX: 'auto', margin: 0, lineHeight: 1.65 }}>
            <code
              dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(highlighted) }}
              style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6' }}
            />
          </pre>
        </div>
      );
    },

    // Images — lightbox
    img({ src, alt }) {
      return <LightboxImage src={src || ''} alt={alt || ''} />;
    },

    // Links — smart rendering based on extension
    a({ href, children }) {
      const ext = getExt(href || '');
      if (IMAGE_EXT.has(ext)) return <LightboxImage src={href} alt={typeof children === 'string' ? children : ''} />;
      if (VIDEO_EXT.has(ext)) return <VideoPlayer src={href}>{children}</VideoPlayer>;
      if (AUDIO_EXT.has(ext)) return <AudioPlayer src={href} />;
      if (ext === 'pdf') return <PdfEmbed src={href} text={typeof children === 'string' ? children : ''} />;
      // Attachment file (from /api/uploads/... or legacy /uploads/...)
      if (href && (href.startsWith('/api/uploads/') || href.startsWith('/uploads/'))) return <FileLink href={href} accent={accent}>{children}</FileLink>;
      // Regular link
      return (
        <a href={href} target="_blank" rel="noreferrer" style={{ color: accent, textDecoration: 'none', borderBottom: `1px solid ${accent}55`, paddingBottom: 1, transition: 'border-color .1s' }}
          onMouseEnter={e => e.currentTarget.style.borderBottomColor = accent}
          onMouseLeave={e => e.currentTarget.style.borderBottomColor = `${accent}55`}
        >
          {children}
        </a>
      );
    },

    // Headings
    h1({ children }) {
      return <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', margin: '6px 0 14px', fontFamily: 'Space Grotesk', borderBottom: '1px solid #2a2d35', paddingBottom: 10, lineHeight: 1.3 }}>{children}</h1>;
    },
    h2({ children }) {
      return <h2 style={{ fontSize: 16, fontWeight: 700, color: '#e0e4ec', margin: '20px 0 10px', fontFamily: 'Space Grotesk', lineHeight: 1.35 }}>{children}</h2>;
    },
    h3({ children }) {
      return <h3 style={{ fontSize: 14, fontWeight: 600, color: '#d0d4dc', margin: '16px 0 8px', fontFamily: 'Space Grotesk' }}>{children}</h3>;
    },
    h4({ children }) {
      return <h4 style={{ fontSize: 13, fontWeight: 600, color: '#c8cdd6', margin: '12px 0 6px', fontFamily: 'Space Grotesk' }}>{children}</h4>;
    },

    // Paragraphs
    p({ children }) {
      return <p style={{ fontSize: 13, lineHeight: 1.8, color: '#b8bdc9', margin: '6px 0 10px' }}>{children}</p>;
    },

    // Lists
    ul({ children }) {
      return <ul style={{ margin: '6px 0 10px', paddingLeft: 20, listStyle: 'none' }}>{children}</ul>;
    },
    ol({ children }) {
      return <ol style={{ margin: '6px 0 10px', paddingLeft: 20 }}>{children}</ol>;
    },
    li({ children, checked }) {
      if (checked !== null && checked !== undefined) {
        // Task list item
        return (
          <li style={{ display: 'flex', alignItems: 'flex-start', gap: 8, margin: '4px 0', fontSize: 13, color: checked ? '#606570' : '#b8bdc9', textDecoration: checked ? 'line-through' : 'none' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 14, height: 14, minWidth: 14, borderRadius: 3, border: `1.5px solid ${checked ? '#39d353' : '#404550'}`, background: checked ? '#39d35322' : 'transparent', marginTop: 2 }}>
              {checked && <span style={{ color: '#39d353', fontSize: 10, lineHeight: 1 }}>✓</span>}
            </span>
            <span>{children}</span>
          </li>
        );
      }
      return (
        <li style={{ display: 'flex', alignItems: 'flex-start', gap: 8, margin: '3px 0', fontSize: 13, lineHeight: 1.7, color: '#b8bdc9' }}>
          <span style={{ color: accent, marginTop: 5, fontSize: 8, flexShrink: 0 }}>◆</span>
          <span>{children}</span>
        </li>
      );
    },

    // Blockquote
    blockquote({ children }) {
      return (
        <blockquote style={{ borderLeft: `3px solid ${accent}`, margin: '10px 0', padding: '8px 16px', background: `${accent}08`, borderRadius: '0 6px 6px 0' }}>
          <div style={{ color: '#9098a8', fontStyle: 'italic' }}>{children}</div>
        </blockquote>
      );
    },

    // Table
    table({ children }) {
      return (
        <div style={{ overflowX: 'auto', margin: '12px 0', borderRadius: 8, border: '1px solid #2a2d35' }}>
          <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 400 }}>{children}</table>
        </div>
      );
    },
    thead({ children }) {
      return <thead style={{ background: '#0d0f14' }}>{children}</thead>;
    },
    th({ children }) {
      return <th style={{ padding: '8px 14px', fontSize: 11, color: '#808590', fontFamily: 'JetBrains Mono', textAlign: 'left', borderBottom: '1px solid #2a2d35', whiteSpace: 'nowrap', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{children}</th>;
    },
    td({ children }) {
      return <td style={{ padding: '7px 14px', fontSize: 12, color: '#c8cdd6', borderBottom: '1px solid #1a1c22', verticalAlign: 'top' }}>{children}</td>;
    },
    tr({ children }) {
      return <tr style={{ transition: 'background .1s' }} onMouseEnter={e => e.currentTarget.style.background = '#ffffff04'} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>{children}</tr>;
    },

    // HR
    hr() {
      return <hr style={{ border: 'none', borderTop: '1px solid #2a2d35', margin: '20px 0' }} />;
    },

    // Strong / em
    strong({ children }) {
      return <strong style={{ color: '#f0f2f6', fontWeight: 700 }}>{children}</strong>;
    },
    em({ children }) {
      return <em style={{ color: '#c8cdd6', fontStyle: 'italic' }}>{children}</em>;
    },

    // Strikethrough (GFM)
    del({ children }) {
      return <del style={{ color: '#505560', textDecoration: 'line-through' }}>{children}</del>;
    },

    // Pre (wraps code, handled above but fallback)
    pre({ children }) {
      return <div style={{ margin: '14px 0' }}>{children}</div>;
    },
  };
}

export default function MdPreview({ content = '', accent = '#cc2233' }) {
  const components = buildComponents(accent);
  return (
    <div style={{ maxWidth: 820, lineHeight: 1.7 }}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={components}
        skipHtml={false}
      >
        {content || ''}
      </ReactMarkdown>
    </div>
  );
}
