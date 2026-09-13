const destination = 'https://dadieng.dadiengalfred.chatgpt.site/console';

export default {
  async fetch(request) {
    const source = new URL(request.url);
    const target = new URL(destination);
    target.search = source.search;
    target.hash = source.hash;
    return Response.redirect(target.toString(), 308);
  },
};
