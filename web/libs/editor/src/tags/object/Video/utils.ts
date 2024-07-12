export function extractProjectIdFromPath(url: string) {  
  const pathParts = url.split('/');  
  const projectIdIndex = pathParts.indexOf('projects') + 1;  
  if (projectIdIndex < pathParts.length) {  
      return pathParts[projectIdIndex];  
  }  
  return null; 
}  