'use client';

import { ReactNode, useRef } from 'react';
import { motion } from 'framer-motion';

interface RevealProps {
  children: ReactNode;
  className?: string;
}

const Reveal = ({ children, className = '' }: RevealProps) => {
  const ref = useRef<HTMLDivElement>(null);

  return (
    <div ref={ref} className={className}>
      <motion.div
        initial={{ y: 40, opacity: 0 }}
        whileInView={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.2 }}
        viewport={{ once: true, amount: 0.8 }}
      >
        {children}
      </motion.div>
    </div>
  );
};

export default Reveal;
