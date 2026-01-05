// ====================================================================
// frontend\src\components\ui\Textarea.jsx
// 📝 Textarea — Multi-line input
// ====================================================================

export default function Textarea({ label, error, className = "", ...props }) {
  return (
    <div>
      {label && <label className="block mb-1 text-sm font-medium text-white">{label}</label>}
      <textarea
        className={`w-full p-3 h-28 rounded-lg bg-white/20 text-white border border-white/30 placeholder-white/60 focus:border-namibia-green transition ${className}`}
        {...props}
      />
      {error && <p className="text-red-300 text-sm mt-1">{error}</p>}
    </div>
  );
}