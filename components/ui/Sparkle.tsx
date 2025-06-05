"use client";

import React, { useRef } from "react";
import {
  motion,
  useAnimationFrame,
  useMotionTemplate,
  useMotionValue,
  useTransform,
} from "framer-motion";
import { cn } from "@/lib/utils";

type SparkleProps = {
  children: React.ReactNode;
  as?: React.ElementType;
  duration?: number;
  className?: string;
  [key: string]: any;
};

export function Sparkle({
  children,
  as: Component = "button",
  duration = 2000,
  className = "",
  ...otherProps
}: SparkleProps) {

  return (
    <Component
      className="relative bg-transparent text-xl p-[1px] overflow-hidden rounded-3xl"
      {...otherProps}
    >
      <div
        className="absolute inset-0 rounded-3xl"
      >
        <SparkleBox duration={duration} rx="30%" ry="30%">
          <div
            className="h-20 w-20 opacity-80 bg-[radial-gradient(purple_70%,transparent_80%)] "
          />
        </SparkleBox>
      </div>
      <div
        className={cn(
          "relative rounded-3xl flex items-center justify-center w-full h-full text-sm text-white border border-white/[0.1] bg-purple-900/[0.5] backdrop-blur-xl",
          className
        )}
      >
        {children}
      </div>
    </Component>
  );
}

type SparkleBoxProps = {
  children: React.ReactNode;
  duration?: number;
  rx?: string;
  ry?: string;
  [key: string]: any;
};

export const SparkleBox = ({
  children,
  duration = 2000,
  rx = "0%",
  ry = "0%",
  ...otherProps
}: SparkleBoxProps) => {
  const pathRef = useRef<SVGRectElement | null>(null);
  const progress = useMotionValue(0);

  useAnimationFrame((time) => {
    const length = pathRef.current?.getTotalLength();
    if (length) {
      const pxPerMs = length / duration;
      progress.set((time * pxPerMs) % length);
    }
  });

  const x = useTransform(progress, (val) =>
    pathRef.current?.getPointAtLength(val).x
  );
  const y = useTransform(progress, (val) =>
    pathRef.current?.getPointAtLength(val).y
  );

  const transform = useMotionTemplate`translateX(${x}px) translateY(${y}px) translateX(-50%) translateY(-50%)`;

  return (
    <>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="absolute w-full h-full"
        preserveAspectRatio="none"
        {...otherProps}
      >
        <rect ref={pathRef} fill="none" width="100%" height="100%" rx={rx} ry={ry} />
      </svg>
      <motion.div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          transform,
        }}
      >
        {children}
      </motion.div>
    </>
  );
};
