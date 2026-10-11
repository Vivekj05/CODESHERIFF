"use client";

import { motion, useReducedMotion } from "motion/react";

/** Fades a section in the first time it scrolls into view, and not at all for reduced motion. */
export function Reveal({ children, className }: { children: React.ReactNode; className?: string }) {
  const still = useReducedMotion() ?? false;
  if (still) return <div className={className}>{children}</div>;
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 12 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.3, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}
