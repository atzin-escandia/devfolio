"use client";

import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import DownloadCV from "./DownloadCV";
import { Socials } from "./Socials";

const NAV_CONTAINER_CLASSES = cn(
  "flex fixed z-[5000] top-10 right-0 sm:gap-5 p-2 sm:px-5 sm:py-4 rounded-l-full border border-white/20"
);

const NAV_CONTAINER_STYLES: React.CSSProperties = {
  backgroundColor: "rgba(255, 255, 255, 0.1)",
  backdropFilter: "blur(10px)",
};

const FloatingBar = () => {
  return (
    <AnimatePresence mode="wait">
      <motion.div
        initial={{ opacity: 1, x: 100 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ opacity: 0, x: 100 }}
        transition={{ duration: 0.3 }}
        className={NAV_CONTAINER_CLASSES}
        style={NAV_CONTAINER_STYLES}
      >
        <Socials />
        <DownloadCV fileUrl="assets/CV.pdf" fileName="Atzin-Escandia-CV.pdf" />
      </motion.div>
    </AnimatePresence>
  );
};

export default FloatingBar;
