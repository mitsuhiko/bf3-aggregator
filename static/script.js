$(function() {
  /* auto hide flashed messages */
  var flashes = $('div.flash');
  if (flashes.length > 0)
    window.setTimeout(function() {
      flashes.animate({'height': 'hide', 'opacity': 'hide'});
    }, 3000);

  /* enable the favorite/unfavorite link */
  $('span.favorite a').bind('click', function() {
    var link = $(this);
    var itemId = link.parent().parent().parent().attr('id').split('-')[1];
    var state = link.is('.fav');
    $.ajax($ROOT_URL + '_favorite', {
      type: 'POST',
      data: {
        id:     itemId,
        state:  state ? 'off' : 'on'
      },
      complete: function() {
        link.toggleClass('fav', !state);
        link.toggleClass('unfav', state);
      }
    });
    return false;
  }).attr('href', '#');
});
