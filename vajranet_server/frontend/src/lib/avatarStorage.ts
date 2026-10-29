// Avatar state, backed by the user profile on the server.
//
// The avatar id and uploaded photo live on vajra_users and arrive with every
// profile response; the localStorage 'user' object is just the client-side
// cache of that profile. This makes avatars follow the account across devices
// and keeps them private per user (the backend only ever serves your own).
//
// Reads go through useAvatar()/getAvatar(); writes go through saveAvatar(),
// which persists to the server first, then updates the cached user and
// notifies subscribers.
import { useSyncExternalStore } from "react";
import { updateAvatar } from "../api/api";
import { getStoredUser, sanitizeUserForCache } from "../services/auth";

export const CUSTOM_AVATAR_ID = 999;

const AVATAR_CHANGE_EVENT = "avatar-change";

// One-time cleanup of avatar caches written by older builds (global, then
// per-user localStorage keys). The server is the source of truth, so clear the
// leftovers rather than let old photos linger in a shared browser.
try {
  Object.keys(localStorage)
    .filter(
      (k) =>
        k.startsWith("vajra_avatar_id") ||
        k.startsWith("vajra_custom_avatar_image")
    )
    .forEach((k) => localStorage.removeItem(k));
} catch {
  // storage disabled — nothing to clean
}

export interface StoredAvatar {
  id: number;
  image: string | null;
}

export const getAvatar = (): StoredAvatar => {
  const user = getStoredUser();
  return {
    id: Number(user?.avatar_id ?? 1),
    image: user?.avatar_image ?? null,
  };
};

// Persist the selection (and optionally a new uploaded image) to the server,
// then sync the cached user object and notify subscribers. Rejects if the
// server rejects the change — callers decide how to surface that.
export const saveAvatar = async (id: number, image?: string): Promise<void> => {
  const res = await updateAvatar({ avatarId: id, avatarImage: image });
  const user = getStoredUser();
  if (user) {
    localStorage.setItem(
      "user",
      JSON.stringify(sanitizeUserForCache({
        ...user,
        avatar_id: res?.data?.avatar_id ?? id,
        avatar_image: res?.data?.avatar_image ?? user.avatar_image ?? null,
      }))
    );
  }
  window.dispatchEvent(new Event(AVATAR_CHANGE_EVENT));
};

// useSyncExternalStore requires a referentially stable snapshot, so cache it
// and only swap when the underlying values actually changed.
let snapshot: StoredAvatar = getAvatar();

const readSnapshot = (): StoredAvatar => {
  const next = getAvatar();
  if (next.id !== snapshot.id || next.image !== snapshot.image) {
    snapshot = next;
  }
  return snapshot;
};

const subscribe = (onChange: () => void): (() => void) => {
  // Same-tab saves and account switches arrive as window events; edits from
  // other tabs arrive as storage events on the cached 'user' object.
  const onStorage = (e: StorageEvent) => {
    if (!e.key || e.key === "user") onChange();
  };
  window.addEventListener(AVATAR_CHANGE_EVENT, onChange);
  window.addEventListener("auth-change", onChange);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(AVATAR_CHANGE_EVENT, onChange);
    window.removeEventListener("auth-change", onChange);
    window.removeEventListener("storage", onStorage);
  };
};

export const useAvatar = (): StoredAvatar =>
  useSyncExternalStore(subscribe, readSnapshot);
