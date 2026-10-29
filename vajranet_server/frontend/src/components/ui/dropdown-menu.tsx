import * as React from "react"
import { Menu as MenuPrimitive } from "@base-ui/react/menu"

import { cn } from "@/lib/utils"

function DropdownMenu(props: MenuPrimitive.Root.Props) {
  return <MenuPrimitive.Root data-slot="dropdown-menu" {...props} />
}

function DropdownMenuTrigger({ className, ...props }: MenuPrimitive.Trigger.Props) {
  return (
    <MenuPrimitive.Trigger
      data-slot="dropdown-menu-trigger"
      className={cn(
        "inline-flex items-center justify-center rounded-full border border-slate-200 bg-slate-50 p-1.5 text-slate-500 outline-none transition-all duration-150",
        "hover:border-slate-300 hover:bg-slate-100 hover:text-slate-700 hover:shadow-sm",
        "active:scale-95",
        "focus-visible:border-blue-300 focus-visible:bg-blue-50 focus-visible:text-blue-700 focus-visible:ring-4 focus-visible:ring-blue-100",
        "data-[popup-open]:border-blue-300 data-[popup-open]:bg-blue-50 data-[popup-open]:text-blue-700 data-[popup-open]:shadow-sm",
        className
      )}
      {...props}
    />
  )
}

function DropdownMenuContent({
  className,
  children,
  sideOffset = 6,
  align = "end",
  ...props
}: MenuPrimitive.Positioner.Props &
  Pick<MenuPrimitive.Popup.Props, "className" | "children">) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Positioner
        data-slot="dropdown-menu-positioner"
        sideOffset={sideOffset}
        align={align}
        className="z-50 outline-none"
        {...props}
      >
        <MenuPrimitive.Popup
          data-slot="dropdown-menu-content"
          className={cn(
            "min-w-[200px] origin-(--transform-origin) overflow-hidden rounded-xl border border-slate-200 bg-white p-1.5 shadow-lg outline-none",
            "transition-[transform,opacity] duration-150 ease-out",
            "data-[starting-style]:scale-95 data-[starting-style]:opacity-0",
            "data-[ending-style]:scale-95 data-[ending-style]:opacity-0",
            className
          )}
        >
          {children}
        </MenuPrimitive.Popup>
      </MenuPrimitive.Positioner>
    </MenuPrimitive.Portal>
  )
}

function DropdownMenuItem({
  className,
  variant = "default",
  ...props
}: MenuPrimitive.Item.Props & { variant?: "default" | "destructive" }) {
  return (
    <MenuPrimitive.Item
      data-slot="dropdown-menu-item"
      data-variant={variant}
      className={cn(
        "flex w-full cursor-pointer select-none items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium text-slate-700 outline-none",
        "data-[highlighted]:bg-blue-50 data-[highlighted]:text-blue-900",
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
        "data-[variant=destructive]:text-red-600",
        "data-[variant=destructive]:data-[highlighted]:bg-red-50 data-[variant=destructive]:data-[highlighted]:text-red-700",
        "[&_svg]:shrink-0 [&_svg]:text-slate-400 data-[highlighted]:[&_svg]:text-current data-[variant=destructive]:[&_svg]:text-red-500",
        className
      )}
      {...props}
    />
  )
}

function DropdownMenuLabel({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="dropdown-menu-label"
      className={cn("px-2.5 py-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400", className)}
      {...props}
    />
  )
}

function DropdownMenuSeparator({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="dropdown-menu-separator"
      className={cn("-mx-1.5 my-1.5 h-px bg-slate-100", className)}
      {...props}
    />
  )
}

export {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
}
