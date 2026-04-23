/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./internal/web/**/*.go",
  ],
  darkMode: "class",
  theme: {
      extend: {
          colors: {
              "background": "#10141a",
              "surface": "#10141a",
              "surface-container": "#1c2026",
              "surface-container-low": "#181c22",
              "surface-container-highest": "#31353c",
              "surface-container-high": "#262a31",
              "surface-container-lowest": "#0a0e14",
              "surface-variant": "#31353c",
              "on-surface": "#dfe2eb",
              "on-surface-variant": "#c2c6d7",
              "primary": "#00daf3",
              "primary-container": "#009fb2",
              "on-primary": "#00363d",
              "secondary": "#ffb4a2",
              "tertiary": "#ffb778",
              "tertiary-container": "#d77900",
              "error": "#ffb4ab",
              "error-container": "#93000a",
              "on-error": "#690005",
              "outline-variant": "#424655"
          },
          fontFamily: {
              sans: ['Inter', 'sans-serif'],
              display: ['Space Grotesk', 'sans-serif'],
              label: ['Inter', 'sans-serif'],
              body: ['Inter', 'sans-serif']
          }
      }
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/container-queries')
  ],
}
