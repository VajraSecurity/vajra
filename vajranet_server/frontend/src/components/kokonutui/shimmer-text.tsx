"use client";

/**
 * @author: @dorianbaffier
 * @description: Shimmer Text
 * @version: 1.0.0
 * @date: 2025-06-26
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

import { motion } from "motion/react";
import { cn } from "@/lib/utils";

interface Text_01Props {
  text: string;
  className?: string;
}

export default function ShimmerText({
  text = "Text Shimmer",
  className,
}: Text_01Props) {
  return (
    <motion.span
      animate={{ backgroundPosition: ["200% center", "-200% center"] }}
      className={cn(
        "bg-[length:200%_100%] bg-gradient-to-r from-white via-blue-200 to-white bg-clip-text text-transparent font-semibold",
        className
      )}
      transition={{ duration: 2.5, ease: "linear", repeat: Number.POSITIVE_INFINITY }}
    >
      {text}
    </motion.span>
  );
}
