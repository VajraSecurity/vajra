import { useState } from 'react';

export const GroupCell = ({ groupIds, groupsMap, openUpward }: { groupIds: string[]; groupsMap: Record<string, string>; openUpward?: boolean }) => {
  const [open, setOpen] = useState(false);
  if (!Array.isArray(groupIds) || groupIds.length === 0) return <span>-</span>;

  const groupNames = groupIds.map(id => groupsMap[id] || id);
  const firstGroup = groupNames[0];
  const remainingCount = groupNames.length - 1;

  return (
    <div className="flex items-center gap-1 group/groupcell relative">
      <span className={"inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium tracking-wider border shadow-sm"}>
        {firstGroup}
      </span>
      {remainingCount > 0 && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setOpen((v) => !v);
          }}
          className="text-xs font-semibold text-black-600 bg-blue-50 px-1.5 py-0.5 rounded-md cursor-pointer"
          aria-expanded={open}
          aria-label="Show all assigned groups"
        >
          +{remainingCount}
        </button>
      )}

      <div
        className={`pointer-events-auto absolute left-0 z-50 w-max max-w-[calc(100vw-2rem)] rounded-lg border border-slate-200 bg-white p-2 shadow-lg group-hover/groupcell:block ${
          openUpward ? 'bottom-full mb-1' : 'top-full mt-1'
        } ${open ? 'block' : 'hidden'}`}
      >
        <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Assigned Groups</div>
        <div className="flex flex-col gap-1">
          {groupNames.map((name, i) => (
            <div key={i} className="text-xs text-slate-700">{name}</div>
          ))}
        </div>
      </div>
    </div>
  );
};
