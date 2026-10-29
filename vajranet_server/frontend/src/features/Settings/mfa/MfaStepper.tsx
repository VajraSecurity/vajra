import { motion } from "motion/react";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { MFA_STEPS } from "./constants";

interface MfaStepperProps {
  currentStep: number;
}

export function MfaStepper({ currentStep }: MfaStepperProps) {
  const steps = MFA_STEPS;
  const progress = ((currentStep - 1) / (steps.length - 1)) * 100;
  const activeTitle = steps.find((s) => s.id === currentStep)?.title ?? "";

  return (
    <div>
      {/* Compact mobile progress */}
      <div className="sm:hidden">
        <div className="mb-1.5 flex items-center justify-between">
          <span className="text-[11px] text-gray-500">
            Step {currentStep} of {steps.length}
          </span>
          <span className="text-[11px] font-semibold text-gray-900">{activeTitle}</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-200">
          <motion.div
            className="h-full rounded-full bg-blue-600"
            initial={false}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          />
        </div>
      </div>

      {/* Full horizontal stepper */}
      <ol className="hidden items-start sm:flex" aria-label="Two-factor authentication setup progress">
        {steps.map((step, i) => {
          const state = step.id < currentStep ? "complete" : step.id === currentStep ? "current" : "upcoming";
          return (
            <li key={step.id} className={cn("flex items-center", i !== steps.length - 1 && "flex-1")}>
              <div className="flex flex-col items-center gap-1.5">
                <div
                  aria-current={state === "current" ? "step" : undefined}
                  className={cn(
                    "flex size-9 shrink-0 items-center justify-center rounded-full border-2 text-sm font-bold transition-all duration-200",
                    state === "complete" && "border-blue-600 bg-blue-600 text-white",
                    state === "current" && "border-blue-600 bg-blue-600 text-white ring-4 ring-blue-100",
                    state === "upcoming" && "border-gray-200 bg-white text-gray-400"
                  )}
                >
                  {state === "complete" ? <Check className="size-4" aria-hidden="true" /> : step.id}
                </div>
                <span
                  className={cn(
                    "text-center text-[10.5px] leading-tight",
                    state === "current" && "font-semibold text-blue-600",
                    state === "complete" && "font-medium text-gray-900",
                    state === "upcoming" && "text-gray-500"
                  )}
                >
                  {step.title}
                </span>
              </div>
              {i !== steps.length - 1 && (
                <div className="relative mx-2 h-0.5 flex-1 -translate-y-3.5 overflow-hidden rounded bg-gray-200">
                  <motion.div
                    className="absolute inset-y-0 left-0 rounded bg-blue-600"
                    initial={false}
                    animate={{ width: step.id < currentStep ? "100%" : "0%" }}
                    transition={{ duration: 0.3, ease: "easeOut" }}
                  />
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
