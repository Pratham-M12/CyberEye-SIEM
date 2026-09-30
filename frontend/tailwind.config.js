/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Enterprise SIEM Theme
        void: "#242424",
        panel: "#343434",
        raised: "#3b3b3b",
        hairline: "#505050",
        surface: '#404040',

        ink:{
          primary:"#ffffff",
          secondary:"#d2d2d2",
          muted:"#a8a8a8",
          dim:"#707070",
        },

        accent: {
          DEFAULT:"#ff5a1f",
          dim:"#ff7d42",
          hover: '#FF7A3D',
          soft: '#FFEEE8',
          dark: '#D9480F',
        },

        severity: {
          critical: '#E53935',
          high: '#FB8C00',
          medium: '#FBC02D',
          low: '#9E9E9E',
        },

        success: '#34A853',
        warning: '#F9AB00',
      },

      fontFamily: {
        mono: [
          '"JetBrains Mono"',
          'ui-monospace',
          'SFMono-Regular',
          'monospace',
        ],
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          'sans-serif',
        ],
      },

      boxShadow: {
        panel: '0 4px 14px rgba(0,0,0,.28)',
        raised: '0 6px 20px rgba(0,0,0,.35)',
      },

      borderRadius: {
        panel: '8px',
      },

      keyframes: {
        scanline: {
          '0%': {
            transform: 'translateX(-100%)',
          },
          '100%': {
            transform: 'translateX(100%)',
          },
        },

        pulseIn: {
          '0%': {
            boxShadow: '0 0 0 0 rgba(255,90,31,.35)',
          },

          '100%': {
            boxShadow: '0 0 0 10px rgba(255,90,31,0)',
          },
        },

        fadeSlide: {
          '0%': {
            opacity: '0',
            transform: 'translateY(10px)',
          },

          '100%': {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
      },

      animation: {
        scanline: 'scanline 4s linear infinite',
        'pulse-in': 'pulseIn 1.1s ease-out',
        fade: 'fadeSlide .35s ease',
      },
      borderRadius: {
        panel: "10px",
      },

      boxShadow: {
        panel: "0 6px 18px rgba(0,0,0,.30)",
      },

      backgroundImage: {
        panel:
          "linear-gradient(180deg,#3a3a3a 0%, #343434 100%)",

        widget:
          "linear-gradient(180deg,#363636 0%, #2f2f2f 100%)",
      },
    },
  },
  plugins: [],
};