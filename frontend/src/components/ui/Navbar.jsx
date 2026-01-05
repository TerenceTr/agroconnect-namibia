// frontend/src/components/ui/Navbar.jsx
import React from "react";
import { Menu } from "lucide-react";

export function Navbar({ title, onMenu }) {
  return (
    <header className="bg-white/10 backdrop-blur-xl border-b border-white/10 shadow-glass px-4 py-3 flex items-center justify-between">
      <button className="lg:hidden text-white" onClick={onMenu}>
        <Menu size={26} />
      </button>

      <h1 className="text-lg font-semibold tracking-wide text-white">
        {title}
      </h1>
    </header>
  );
}

export default Navbar;
