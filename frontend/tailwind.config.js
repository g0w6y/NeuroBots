/** @type {import('tailwindcss').Config} */

// Project0 design system — Material 3 dark, cool obsidian + cyber blue.
//
// The existing semantic names (canvas/ink/accent/risk) are kept and remapped to
// the new palette rather than renamed. Every component already speaks in those
// terms, so remapping moves the whole dashboard onto the new system at once and
// keeps a single source of truth for "what colour is danger" - which matters
// here because those colours carry meaning (a block is red, a challenge amber),
// not decoration. The raw M3 role names are exported alongside for the shell.
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: '#131315',
          panel: '#201f22',
          raised: '#2a2a2c',
          sunken: '#0e0e10',
          line: '#2f2f33',
          'line-strong': '#424754'
        },
        ink: {
          DEFAULT: '#e5e1e4',
          muted: '#c2c6d6',
          faint: '#8c909f'
        },
        accent: {
          DEFAULT: '#adc6ff',
          strong: '#d8e2ff',
          dim: '#00285d'
        },
        violet: {
          DEFAULT: '#4d8eff',
          dim: '#001a42'
        },
        risk: {
          safe: '#4ae176',
          'safe-dim': '#004119',
          caution: '#ffb95f',
          'caution-dim': '#3e2400',
          danger: '#ffb4ab',
          'danger-dim': '#93000a'
        },

        // M3 role names, for the Project0 shell markup
        surface: {
          DEFAULT: '#131315',
          container: '#201f22',
          'container-low': '#1c1b1d',
          'container-lowest': '#0e0e10',
          'container-high': '#2a2a2c',
          'container-highest': '#353437',
          variant: '#353437',
          bright: '#39393b'
        },
        outline: {
          DEFAULT: '#8c909f',
          variant: '#424754'
        }
      },
      fontFamily: {
        display: ['"Hanken Grotesk"', 'sans-serif'],
        sans: ['"Hanken Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace']
      },
      borderRadius: {
        DEFAULT: '0.125rem',
        lg: '0.25rem',
        xl: '0.5rem'
      },
      letterSpacing: {
        caps: '0.06em'
      },
      animation: {
        'flash-in': 'flash-in 0.6s ease-out',
        breathe: 'breathe 2.4s ease-in-out infinite',
        'pulse-alert': 'pulse-alert 2s cubic-bezier(0.4, 0, 0.6, 1) infinite'
      },
      keyframes: {
        'flash-in': {
          '0%': { backgroundColor: 'rgba(173,198,255,0.16)' },
          '100%': { backgroundColor: 'transparent' }
        },
        breathe: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.45 }
        },
        'pulse-alert': {
          '0%, 100%': { borderColor: 'rgba(255,180,171,0.5)' },
          '50%': { borderColor: 'rgba(255,180,171,1)' }
        }
      }
    }
  },
  plugins: []
};
