export interface IQuery {
    searchTerm?: string
    page?: string
    limit?: string
    sortOrder?: string
    sortBy?: string
    [key: string]: any
}