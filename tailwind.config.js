/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        "text": "#f9f9f9",
        "background": "#000305",
        "primary": "#0ee26e",
        "secondary": "#011927",
        "accent": "#dd6d2c",
        "grgray": "#383838",
        "brwhite": "#e0e0e0"
      }
    },
  },
  plugins: [],
};