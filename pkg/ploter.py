import pandas
import altair as alt
from altair import Column, X, Y, Color, Scale


def plotter(name, x, label):
    df = pandas.DataFrame({"x": [el[0] for el in x], "y": [el[1] for el in x], "z": [el[2] for el in x]})
    chart = alt.Chart(df, title=label[2],
            width=60, height=600).mark_bar().encode(
        column=Column('x',  title=label[3], spacing=75),
        x=X('z', title=""),
        y=Y('y', title=label[4]),
        color=Color('z', title=label[5], scale=Scale(range=['#6fbf4a', '#5f249f']))
    ).configure_view(
        strokeWidth=0.0, width=300
    )

    chart = chart.configure_title(fontSize=25, offset=15)
    chart.save(f"{name}.html")
