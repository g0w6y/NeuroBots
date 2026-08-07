/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: '#131211',
          panel: '#1a1917',
          raised: '#211f1c',
          line: '#2c2925',
          'line-strong': '#3a362f'
        },
        ink: {
          DEFAULT: '#ede9e4',
          muted: '#a39c93',
          faint: '#6b655c'
        },
        accent: {
          DEFAULT: '#4fb3a4',
          strong: '#73cbbe',
          dim: '#16302c'
        },
        violet: {
          DEFAULT: '#9089ce',
          dim: '#211f30'
        },
        risk: {
          safe: '#5fa86f',
          'safe-dim': '#16261b',
          caution: '#c98a3c',
          'caution-dim': '#2e2013',
          danger: '#c85c4a',
          'danger-dim': '#2e1712'
        }
      },
      fontFamily: {
        display: ['"Overpass"', 'sans-serif'],
        sans: ['"IBM Plex Sans"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace']
      },
      animation: {
        'flash-in': 'flash-in 0.6s ease-out',
        breathe: 'breathe 2.4s ease-in-out infinite'
      },
      keyframes: {
        'flash-in': {
          '0%': { backgroundColor: 'rgba(79,179,164,0.16)' },
          '100%': { backgroundColor: 'transparent' }
        },
        breathe: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.45 }
        }
      }
    }
  },
  plugins: []
};
