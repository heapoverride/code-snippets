/// <summary>
/// Calculate hash code for a given string ("Knuth hash")
/// </summary>
/// <param name="str"></param>
/// <returns>Hash code</returns>
public static ulong HashCode(string str)
{
	ulong hash = 3074457345618258791ul;

	unchecked
	{
		for (int i = 0; i < str.Length; i++)
		{
			hash += str[i];
			hash *= 3074457345618258799ul;
		}
	}

	return hash;
}