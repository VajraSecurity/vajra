import { useCallback, useEffect, useMemo, useState } from 'react';
import { ThemeContext } from './useTheme';
import type { Theme } from './useTheme';
// eslint-disable-next-line react-refresh/only-export-components
export { useTheme } from './useTheme';

export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [theme, setThemeState] = useState<Theme>(() => {
        return (localStorage.getItem('vajra-theme') as Theme) ?? 'light';
    });

    useEffect(() => {
        const root = document.documentElement;
        if (theme === 'dark') {
            root.classList.add('dark');
        } else {
            root.classList.remove('dark');
        }
        localStorage.setItem('vajra-theme', theme);
    }, [theme]);

    // Unlike the sibling contexts these callbacks were plain inline arrows, so
    // every ThemeProvider render produced fresh identities and a fresh value
    // object. ThemeProvider wraps the entire authenticated shell.
    const setTheme = useCallback((t: Theme) => setThemeState(t), []);
    const toggleTheme = useCallback(
        () => setThemeState(prev => prev === 'light' ? 'dark' : 'light'),
        [],
    );
    const value = useMemo(
        () => ({ theme, toggleTheme, setTheme }),
        [theme, toggleTheme, setTheme],
    );

    return (
        <ThemeContext.Provider value={value}>
            {children}
        </ThemeContext.Provider>
    );
}
