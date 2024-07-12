export function CallModel(url: string, data: any) {
  return fetch(url, {
    method: 'POST',
    body: data,
  }).then((res) => {
    return res.json().then((data) => {
      return data;
    });
  });
}
