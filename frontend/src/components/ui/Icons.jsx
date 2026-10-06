// frontend/src/components/ui/Icons.jsx
import React from 'react';

/**
 * Common SVG properties for unified stroke weight and scalable sizing.
 */
const defaultProps = {
  fill: 'none',
  viewBox: '0 0 24 24',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': 'true',
};

export function IconShield({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export function IconShieldCheck({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

export function IconAlertTriangle({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export function IconAlertOctagon({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

export function IconAlertCircle({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

export function IconInfo({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}

export function IconCheck({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

export function IconCheckCircle({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}

export function IconClose({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

export function IconSearch({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

export function IconUpload({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  );
}

export function IconUploadCloud({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="16 16 12 12 8 16" />
      <line x1="12" y1="12" x2="12" y2="21" />
      <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" />
      <polyline points="16 16 12 12 8 16" />
    </svg>
  );
}

export function IconFolder({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    </svg>
  );
}

export function IconLock({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

export function IconTrendingUp({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
      <polyline points="17 6 23 6 23 12" />
    </svg>
  );
}

export function IconActivity({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

export function IconBarChart({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <line x1="18" y1="20" x2="18" y2="10" />
      <line x1="12" y1="20" x2="12" y2="4" />
      <line x1="6" y1="20" x2="6" y2="14" />
    </svg>
  );
}

export function IconTarget({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </svg>
  );
}

export function IconCrosshair({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <line x1="22" y1="12" x2="18" y2="12" />
      <line x1="6" y1="12" x2="2" y2="12" />
      <line x1="12" y1="6" x2="12" y2="2" />
      <line x1="12" y1="22" x2="12" y2="18" />
    </svg>
  );
}

export function IconFileText({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

export function IconClock({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}

export function IconGlobe({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

export function IconServer({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}

export function IconLaptop({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <line x1="2" y1="20" x2="22" y2="20" />
    </svg>
  );
}

export function IconPlug({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M12 22v-5" />
      <path d="M9 8V2" />
      <path d="M15 2v6" />
      <path d="M18 8H6a2 2 0 0 0-2 2v2a7 7 0 0 0 14 0v-2a2 2 0 0 0-2-2z" />
    </svg>
  );
}

export function IconUser({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

export function IconUsers({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

export function IconSettings({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

export function IconSparkles({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z" />
      <path d="M5 3v4" />
      <path d="M3 5h4" />
      <path d="M19 17v4" />
      <path d="M17 19h4" />
    </svg>
  );
}

export function IconRefresh({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M21.5 2v6h-6" />
      <path d="M2.5 22v-6h6" />
      <path d="M2 11.5a10 10 0 0 1 18.8-4.3L21.5 8" />
      <path d="M22 12.5a10 10 0 0 1-18.8 4.2L2.5 16" />
    </svg>
  );
}

export function IconZap({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

export function IconPlaybook({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
      <line x1="9" y1="7" x2="15" y2="7" />
      <line x1="9" y1="11" x2="13" y2="11" />
    </svg>
  );
}

export function IconFilter({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
    </svg>
  );
}

export function IconChevronLeft({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}

export function IconChevronRight({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}

export function IconChevronDown({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

export function IconChevronUp({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <polyline points="18 15 12 9 6 15" />
    </svg>
  );
}

export function IconBell({ className = 'h-4 w-4', ...props }) {
  return (
    <svg className={className} {...defaultProps} {...props}>
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}
