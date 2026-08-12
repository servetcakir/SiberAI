export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      className={className}
    >
      <path
        d="M12 2L20 7V17L12 22L4 17V7L12 2Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M12 8L16 10.5V15.5L12 18L8 15.5V10.5L12 8Z"
        stroke="#38bdf8"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}
