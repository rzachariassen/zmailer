typedef struct namelist {
	char		*name;
	struct namelist	*next;
} NAMELIST;

extern void	free_namelist();
extern NAMELIST	*fuzzy();
