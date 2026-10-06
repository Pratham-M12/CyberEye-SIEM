// frontend/src/components/ui/CyberEyeLogo.jsx
import React from 'react';

/**
 * CyberEye Icon / Mark Component
 * Combines shield geometry, cybernetic aperture eye, and network telemetry circuit nodes.
 */
export function CyberEyeMark({
  className = 'h-8 w-8',
  iconColor = '#FF5A1F',
  shieldColor = 'currentColor',
  ...props
}) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
      {...props}
    >
      {/* Outer Defense Shield Contour */}
      <path
        d="M16 2.75 L27 7.25 V15 C27 22.3 22.25 26.9 16 29.25 C9.75 26.9 5 22.3 5 15 V7.25 L16 2.75 Z"
        stroke={shieldColor}
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="text-white/80 transition-colors"
      />

      {/* Cyber Eye Aperture Contour */}
      <path
        d="M8 15 C10.2 11.2 13 9.5 16 9.5 C19 9.5 21.8 11.2 24 15 C21.8 18.8 19 20.5 16 20.5 C13 20.5 10.2 18.8 8 15 Z"
        stroke={iconColor}
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Inner Telemetry Target Ring */}
      <circle
        cx="16"
        cy="15"
        r="4"
        stroke={iconColor}
        strokeWidth="1.5"
        strokeOpacity="0.8"
      />

      {/* Center Iris Core / Focal Sensor */}
      <circle cx="16" cy="15" r="2" fill={iconColor} />
      <circle cx="16" cy="15" r="0.8" fill="#FFFFFF" />

      {/* Lateral Network Nodes & Circuit Traces */}
      <line
        x1="2"
        y1="15"
        x2="6"
        y2="15"
        stroke={iconColor}
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="2.5" cy="15" r="1.25" fill={iconColor} />

      <line
        x1="26"
        y1="15"
        x2="30"
        y2="15"
        stroke={iconColor}
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="29.5" cy="15" r="1.25" fill={iconColor} />

      {/* Vertical Reticle Coordinates */}
      <line
        x1="16"
        y1="5.5"
        x2="16"
        y2="7.5"
        stroke={iconColor}
        strokeWidth="1.25"
        strokeLinecap="round"
      />
      <line
        x1="16"
        y1="22.5"
        x2="16"
        y2="25"
        stroke={iconColor}
        strokeWidth="1.25"
        strokeLinecap="round"
      />
    </svg>
  );
}

/**
 * CyberEye Wordmark Component
 * Clean, technical typography matching Inter & JetBrains Mono design language.
 */
export function CyberEyeWordmark({
  size = 'md',
  showTag = true,
  className = '',
}) {
  const sizeMap = {
    sm: {
      title: 'text-base',
      tag: 'text-[9px] px-1.5 py-0.2',
    },
    md: {
      title: 'text-xl sm:text-2xl',
      tag: 'text-[10px] px-2 py-0.5',
    },
    lg: {
      title: 'text-2xl sm:text-3xl',
      tag: 'text-xs px-2 py-0.5',
    },
  };

  const current = sizeMap[size] || sizeMap.md;

  return (
    <div className={`flex items-baseline gap-2 min-w-0 ${className}`}>
      <span
        className={`font-sans font-bold tracking-tight text-white uppercase ${current.title}`}
      >
        CYBER<span className="text-accent">EYE</span>
      </span>
      {showTag && (
        <span
          className={`font-mono font-semibold tracking-widest uppercase rounded border border-accent/40 bg-accent/10 text-accent ${current.tag}`}
        >
          SIEM
        </span>
      )}
    </div>
  );
}

/**
 * Combined CyberEye Logo Lockup
 * Supports horizontal header layout, compact mobile, or centered login card presentation.
 */
export default function CyberEyeLogo({
  variant = 'horizontal',
  subtitle = 'Enterprise Threat Monitoring Dashboard',
  className = '',
  markClassName = '',
}) {
  if (variant === 'icon') {
    return <CyberEyeMark className={markClassName || 'h-8 w-8'} />;
  }

  if (variant === 'wordmark') {
    return <CyberEyeWordmark className={className} />;
  }

  if (variant === 'login') {
    return (
      <div className={`text-center ${className}`}>
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-hairline/80 bg-raised p-3 shadow-xl shadow-accent/15 transition-transform hover:scale-105">
          <CyberEyeMark className="h-full w-full" />
        </div>
        <div className="mt-4 flex items-center justify-center gap-2">
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white uppercase font-sans">
            CYBER<span className="text-accent">EYE</span>
          </h1>
          <span className="font-mono text-xs font-bold tracking-widest uppercase rounded border border-accent/50 bg-accent/15 px-2 py-0.5 text-accent">
            SIEM
          </span>
        </div>
        {subtitle && (
          <p className="mt-2 text-xs sm:text-sm text-ink-secondary">
            {subtitle}
          </p>
        )}
      </div>
    );
  }

  // Default 'horizontal' lockup for desktop & responsive headers
  return (
    <div className={`flex items-center gap-3 sm:gap-3.5 min-w-0 ${className}`}>
      <div className="flex h-10 w-10 sm:h-11 sm:w-11 shrink-0 items-center justify-center rounded-panel border border-hairline/80 bg-raised p-2 shadow-md">
        <CyberEyeMark className={markClassName || 'h-full w-full'} />
      </div>
      <div className="min-w-0">
        <CyberEyeWordmark size="md" showTag={true} />
        {subtitle && (
          <p className="text-[11px] sm:text-xs text-ink-secondary truncate leading-tight mt-0.5">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
