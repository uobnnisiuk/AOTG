using System;
using System.Collections.Generic;

public sealed class BatchRegistry
{
    private readonly HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);

    public bool TryRegister(IEnumerable<string> batch)
    {
        foreach (string id in batch)
        {
            if (!ids.Add(id))
                return false;
        }

        return true;
    }

    public bool Contains(string id) => ids.Contains(id);
}
